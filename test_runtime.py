"""Offline v6 regression tests. No external APIs or real media are modified."""
import os
import pathlib
import tempfile
import sqlite3
import threading
import unittest
from unittest.mock import patch, MagicMock

_tmp = tempfile.TemporaryDirectory()
os.environ.update({
    'DATABASE_PATH': str(pathlib.Path(_tmp.name) / 'requests.sqlite3'),
    'PLEX_URL': 'http://127.0.0.1:32400',
    'PLEX_TOKEN': 'test-owner-token-do-not-use',
    'MAINTAINERR_URL': 'http://maintainerr:6246',
    'MOVIE_COLLECTION_ID': '1',
    'SHOW_COLLECTION_ID': '2',
    'KIDS_MOVIE_COLLECTION_ID': '3',
    'ANIME_MOVIE_COLLECTION_ID': '4',
    'KIDS_SHOW_COLLECTION_ID': '5',
    'ANIME_SHOW_COLLECTION_ID': '6',
    'MIN_DELETE_DAYS': '7',
    'PORTAL_HOST': 'cleanup.tb-server.com',
    'SECRET_KEY': 'b' * 64,
})
import app as portal


class PortalTests(unittest.TestCase):
    def setUp(self):
        # Tests share an offline temporary SQLite file. Isolate request state so
        # pagination fixtures do not exhaust another test user's pending quota.
        with portal.conn() as c:
            c.execute('DELETE FROM requests')
        self.client = portal.app.test_client()
        self.url = 'https://cleanup.tb-server.com'
        self.headers = {}
        self.mock_user = patch.object(portal, 'plex_owner_id', return_value='111')
        self.mock_user.start(); self.addCleanup(self.mock_user.stop)

    def req(self, path, method='GET', **kwargs):
        return self.client.open(path, method=method, base_url=self.url, headers=self.headers, **kwargs)

    def csrf(self):
        with self.client.session_transaction(base_url=self.url) as session:
            return session['csrf']

    def logged_in(self, uid):
        with portal.conn() as conn:
            conn.execute('''INSERT OR REPLACE INTO plex_sessions
                (plex_user_id,username,encrypted_token,encrypted_server_token,session_epoch,last_validated)
                VALUES (?,?,?,?,0,?)''',
                (uid, 'testing', portal.fernet.encrypt(b'token'),
                 portal.fernet.encrypt(b'server-token'), int(portal.time.time())))
            epoch = conn.execute("SELECT value FROM portal_meta WHERE name='global_epoch'").fetchone()[0]
        with self.client.session_transaction(base_url=self.url) as session:
            session.update(plex_uid=uid, epoch=0, global_epoch=epoch,
                           csrf='csrf-test')

    def test_anonymous_user_must_authenticate(self):
        r = self.client.get('/', base_url=self.url)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r.headers['Location'])

    def test_spoofed_cloudflare_headers_do_not_grant_access(self):
        r = self.client.get('/decide/1', base_url=self.url, headers={
            'Cf-Access-Authenticated-User-Email': 'owner@example.com',
            'X-Forwarded-User': 'owner'})
        self.assertIn(r.status_code, (302, 403, 405))
        self.assertNotEqual(r.status_code, 200)

    def test_db_rejects_duplicate_active_requests(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:222','801234','movie','Example'))
        with self.assertRaises(sqlite3.IntegrityError):
            with portal.conn() as c:
                c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                          ('plex:333','801234','movie','Example'))

    def test_rejected_media_can_be_requested_again(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title,status) VALUES (?,?,?,?,?)",
                      ('plex:222','801235','movie','Example','rejected'))
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:333','801235','movie','Example'))

    def test_concurrent_db_inserts_only_one_wins(self):
        barrier = threading.Barrier(2)
        results = []
        def writer(uid):
            barrier.wait()
            try:
                with portal.conn() as c:
                    c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                              (uid,'801236','show','Same media'))
                results.append('ok')
            except sqlite3.IntegrityError:
                results.append('duplicate')
        a = threading.Thread(target=writer,args=('plex:222',))
        b = threading.Thread(target=writer,args=('plex:333',))
        a.start();b.start();a.join();b.join()
        self.assertCountEqual(results,['ok','duplicate'])

    def test_collection_library_id_must_match(self):
        configured = {'id':5,'libraryId':'12','type':'show','isActive':True,
                      'arrAction':0,'deleteAfterDays':7}
        with patch.object(portal, 'service_json', return_value=configured):
            self.assertEqual(portal.check_collection(5,'show','12')['id'],5)
            with self.assertRaises(ValueError):
                portal.check_collection(5,'show','13')
        for bad in (None, '', '0', True):
            with self.subTest(libraryId=bad), patch.object(portal,'service_json',return_value={**configured,'libraryId':bad}):
                with self.assertRaises(ValueError):
                    portal.check_collection(5,'show','12')

    def test_unauthed_approval_denied(self):
        r = self.req('/decide/1', 'POST', data={'csrf': 'whatever', 'decision': 'approve'})
        self.assertNotEqual(r.status_code, 200)

    def test_browser_nonce_stored_without_cloudflare_access(self):
        self.req('/login')
        with self.client.session_transaction(base_url=self.url) as ss:
            self.assertTrue(ss.get('browser_nonce'))

    def test_plex_login_page(self):
        r = self.req('/login')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Sign in with Plex', r.data)

    def test_one_day_policy_is_configurable(self):
        self.assertEqual(portal.MIN_DELETE_DAYS, 7)  # test environment sets 7; lower bound is 1
        source = pathlib.Path(portal.__file__).read_text(encoding="utf-8")
        self.assertIn("MIN_DELETE_DAYS = max(1,", source)

    def test_pin_start_requires_csrf(self):
        self.assertEqual(self.req('/auth/plex/start', 'POST').status_code, 403)

    def test_pin_start_rate_limit(self):
        self.req('/login')
        with patch.object(portal, 'plex_cloud', return_value={'id': 123456, 'code': 'sufficiently-long-code'}):
            for _ in range(10):
                response = self.req('/auth/plex/start', 'POST', data={'csrf': self.csrf()})
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'Continue to Plex', response.data)
            response = self.req('/auth/plex/start', 'POST', data={'csrf': self.csrf()})
            self.assertEqual(response.status_code, 429)

    def test_plex_callback_requires_nonce(self):
        with self.client.session_transaction(base_url=self.url) as session:
            session.update(plex_pin_id=1234, plex_pin_started=int(portal.time.time()),
                           pin_browser_nonce='test-browser', browser_nonce='test-browser', pin_nonce='secret-nonce')
        response = self.req('/auth/plex/callback?nonce=incorrect')
        self.assertEqual(response.status_code, 403)

    def test_requester_cannot_approve(self):
        self.logged_in('222')
        r = self.req('/decide/1', 'POST', data={'csrf': 'csrf-test', 'decision': 'approve'})
        self.assertEqual(r.status_code, 403)

    def test_requester_cannot_revoke(self):
        self.logged_in('222')
        self.assertEqual(self.req('/admin/revoke-sessions', 'POST', data={'csrf':'csrf-test'}).status_code, 403)

    def test_admin_all_requests_includes_other_users(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:222','908901','show','Shared User Request'))
        self.logged_in('111')
        page = self.req('/admin/requests')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Shared User Request', page.data)
        self.assertIn(b'Approve', page.data)
        with patch.object(portal, 'plex_libraries', return_value=[]):
            dashboard = self.req('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b'/admin/requests', dashboard.data)
        self.assertIn(b'PLEX SERVER ADMINISTRATION', dashboard.data)

    def test_requester_cannot_read_all_requests(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:333','908902','movie','Private Request'))
        self.logged_in('222')
        self.assertEqual(self.req('/admin/requests').status_code, 403)
        with patch.object(portal, 'plex_libraries', return_value=[]):
            dashboard = self.req('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(b'Private Request', dashboard.data)
        self.assertNotIn(b'/admin/requests', dashboard.data)
        self.assertIn(b'YOUR SHARED PLEX LIBRARY', dashboard.data)

    def test_admin_all_requests_paginates(self):
        with portal.conn() as c:
            for i in range(27):
                c.execute('INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)',
                          ('plex:222',str(909000+i),'movie',f'History item {i}'))
        self.logged_in('111')
        first = self.req('/admin/requests')
        second = self.req('/admin/requests?page=2')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertIn(b'Next', first.data)
        self.assertNotIn(b'History item 0', first.data)
        self.assertIn(b'History item 0', second.data)
        self.assertEqual(self.req('/admin/requests?page=invalid').status_code, 400)

    def test_owner_can_view_and_revoke(self):
        self.logged_in('111')
        with patch.object(portal, 'plex_libraries', return_value=[]):
            self.assertEqual(self.req('/').status_code, 200)
        result = self.req('/admin/revoke-sessions', 'POST', data={'csrf':'csrf-test'})
        self.assertEqual(result.status_code, 302)
        self.assertNotIn('plex_uid', self._session())

    def _session(self):
        with self.client.session_transaction(base_url=self.url) as session:
            return dict(session)

    def test_bulk_rejects_unvalidated_ids(self):
        self.logged_in('222')
        r = self.req('/request/bulk', 'POST', data={'csrf':'csrf-test', 'plex_ids':['../../evil']})
        self.assertEqual(r.status_code, 400)

    def test_bulk_requests_stay_pending(self):
        self.logged_in('222')
        with patch.object(portal, 'plex_item', return_value={'id':'432100', 'title':'Test Film', 'type':'movie', 'section_id':'1'}), \
             patch.object(portal, 'plex_libraries', return_value=[{'id':'1','title':'Movies','type':'movie'}]):
            with patch.object(portal, 'service_json', side_effect=AssertionError('Maintainerr must not be called')):
                r = self.req('/request/bulk', 'POST', data={'csrf':'csrf-test', 'plex_ids':['432100']})
                self.assertEqual(r.status_code, 302)
        with portal.conn() as conn:
            row = conn.execute("SELECT status FROM requests WHERE plex_id='432100'").fetchone()
            self.assertEqual(row['status'], 'pending')

    def test_bulk_request_pending_quota_still_enforced(self):
        self.logged_in('222')
        with portal.conn() as c:
            for i in range(20):
                c.execute('INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)',
                          ('plex:222', str(950000+i), 'movie', f'Pending {i}'))
        media = {'id': '950100', 'title': 'Over Limit', 'type': 'movie', 'section_id': '1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'service_json', side_effect=AssertionError('No Maintainerr calls')):
            response = self.req('/request/bulk', 'POST', data={'csrf': 'csrf-test', 'plex_ids': ['950100']})
        self.assertEqual(response.status_code, 429)
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM requests WHERE requester=?', ('plex:222',)).fetchone()[0], 20)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM requests WHERE plex_id=?', ('950100',)).fetchone()[0], 0)

    def test_six_library_routes(self):
        libraries = [
            {'id': '1', 'title': 'Movies', 'type': 'movie'},
            {'id': '2', 'title': 'TV Shows', 'type': 'show'},
            {'id': '3', 'title': 'Kids Movies', 'type': 'movie'},
            {'id': '4', 'title': 'Anime Movies', 'type': 'movie'},
            {'id': '5', 'title': 'Kids TV Shows', 'type': 'show'},
            {'id': '6', 'title': 'Anime TV Shows', 'type': 'show'},
        ]
        with patch.object(portal, 'plex_libraries', return_value=libraries):
            for number in range(1, 7):
                kind = 'movie' if number in (1, 3, 4) else 'show'
                self.assertEqual(portal.collection_for_item({'section_id': str(number), 'type': kind}), number)
            with self.assertRaises(ValueError):
                portal.collection_for_item({'section_id': '7', 'type': 'movie'})
            with self.assertRaises(ValueError):
                portal.collection_for_item({'section_id': '5', 'type': 'movie'})

    def test_unmapped_library_refused_during_request(self):
        self.logged_in('222')
        with patch.object(portal, 'plex_item', return_value={
            'id':'999993', 'title':'Unmapped film', 'type':'movie', 'section_id':'999'}), \
             patch.object(portal, 'plex_libraries', return_value=[{'id':'1', 'title':'Movies','type':'movie'}]):
            self.req('/request', 'POST', data={'csrf':'csrf-test','plex_id':'999993'})
        with portal.conn() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM requests WHERE plex_id='999993'").fetchone()[0], 0)

    def test_owner_single_request_auto_approved(self):
        self.logged_in('111')
        media = {'id':'990011', 'title':'Owner Movie', 'type':'movie', 'section_id':'1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'check_collection') as chk, \
             patch.object(portal, 'has_membership', side_effect=[False, True]), \
             patch.object(portal, 'service_json', return_value={}) as sent:
            response = self.req('/request', 'POST', data={'csrf':'csrf-test', 'plex_id':'990011'})
        self.assertEqual(response.status_code, 302)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['json']['collectionId'], 1)
        chk.assert_called_once()
        with portal.conn() as c:
            row = c.execute('SELECT status,decided_by FROM requests WHERE plex_id=?', ('990011',)).fetchone()
        self.assertEqual(row['status'], 'approved')
        self.assertEqual(row['decided_by'], 'plex:111')

    def test_owner_ambiguous_submission_never_auto_retries(self):
        self.logged_in('111')
        media = {'id':'990012', 'title':'Uncertain Movie', 'type':'movie', 'section_id':'1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'check_collection'), \
             patch.object(portal, 'has_membership', return_value=False), \
             patch.object(portal, 'service_json', side_effect=portal.requests.Timeout('ambiguous')) as sent:
            self.assertEqual(self.req('/request', 'POST', data={'csrf':'csrf-test','plex_id':'990012'}).status_code, 302)
        sent.assert_called_once()
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE plex_id=?', ('990012',)).fetchone()[0], 'review')
        # Duplicate never triggers another Maintainerr submission.
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'service_json', side_effect=AssertionError('must not retry')):
            self.assertEqual(self.req('/request','POST',data={'csrf':'csrf-test','plex_id':'990012'}).status_code,302)

    def test_requester_history_is_private(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES ('plex:222','991111','movie','Mine Visible')")
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES ('plex:333','991112','movie','Other Hidden')")
        self.logged_in('222')
        response = self.req('/my-requests')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Mine Visible', response.data)
        self.assertNotIn(b'Other Hidden', response.data)

    def test_anonymous_history_requires_login(self):
        response = self.req('/my-requests')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_owner_bulk_auto_approve(self):
        self.logged_in('111')
        items = {'990013': {'id':'990013','title':'Owner Show 1','type':'show','section_id':'5'},
                 '990014': {'id':'990014','title':'Owner Show 2','type':'show','section_id':'5'}}
        with patch.object(portal,'plex_item',side_effect=lambda item,**kw:items[item]), \
             patch.object(portal,'collection_for_item',return_value=5), \
             patch.object(portal,'check_collection'), \
             patch.object(portal,'has_membership',side_effect=[False,True,False,True]), \
             patch.object(portal,'service_json',return_value={}) as sent:
            response = self.req('/request/bulk','POST',data={'csrf':'csrf-test','plex_ids':['990013','990014']})
        self.assertEqual(response.status_code,302)
        self.assertEqual(sent.call_count,2)
        with portal.conn() as c:
            result=c.execute("SELECT status FROM requests WHERE plex_id IN ('990013','990014')").fetchall()
        self.assertEqual([x[0] for x in result],['approved','approved'])

    def test_unauthorized_server_membership_denied(self):
        with patch.object(portal, 'server_identifier', return_value='server-abc'), \
             patch.object(portal, 'plex_cloud', return_value=[{'clientIdentifier':'different-server', 'provides':'server', 'accessToken':'x'}]):
            self.assertIsNone(portal.plex_server_token('user-token'))


class DiscordTests(unittest.TestCase):
    # Reuse fixture helpers without inheriting all PortalTests test methods.
    req = PortalTests.req
    csrf = PortalTests.csrf
    logged_in = PortalTests.logged_in

    def setUp(self):
        PortalTests.setUp(self)
        with portal.conn() as c:
            c.execute('UPDATE discord_settings SET webhook_cipher=NULL, enabled=0, new_request=1, approved=1, rejected=1, review=1 WHERE id=1')

    def test_discord_admin_only(self):
        self.logged_in('222')
        self.assertEqual(self.req('/admin/discord').status_code, 403)
        self.assertEqual(self.req('/admin/discord/save', method='POST', data={'csrf':'csrf-test'}).status_code, 403)
        self.assertEqual(self.req('/admin/discord/test', method='POST', data={'csrf':'csrf-test'}).status_code, 403)
        self.assertEqual(self.req('/admin/discord/remove', method='POST', data={'csrf':'csrf-test'}).status_code, 403)

    def test_discord_webhook_validation(self):
        good='https://discord.com/api/webhooks/123456789012345678/' + 'a'*60
        self.assertEqual(portal.validate_discord_webhook(good),good)
        for bad in ['http://discord.com/api/webhooks/123456789012345678/'+ 'a'*60,
                    'https://discord.com.evil.test/api/webhooks/123456789012345678/'+'a'*60,
                    'https://discord.com@evil.test/api/webhooks/123456789012345678/'+'a'*60,
                    'https://discord.com/api/webhooks/123456789012345678/'+'a'*60+'?wait=true',
                    'https://discord.com/api/webhooks/123456789012345678/'+'a'*60+'#frag']:
            with self.assertRaises(ValueError): portal.validate_discord_webhook(bad)

    def test_discord_saved_encrypted_and_disabled_by_default(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        r=self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','enabled':'on','webhook':hook,'new_request':'on'})
        self.assertEqual(r.status_code,302)
        cfg=portal.discord_config()
        self.assertEqual(cfg['enabled'],1)
        self.assertNotIn(hook.encode(),bytes(cfg['webhook_cipher']))
        self.assertEqual(portal.fernet.decrypt(cfg['webhook_cipher']).decode(), hook)
        self.assertNotIn(hook.encode(), self.req('/admin/discord').data)
        self.req('/admin/discord/remove',method='POST',data={'csrf':'csrf-test'})
        self.assertIsNone(portal.discord_config()['webhook_cipher'])
        self.assertEqual(portal.discord_config()['enabled'],0)

    def test_discord_failure_cannot_interrupt_requests(self):
        with patch.object(portal, 'discord_send', return_value=False):
            row={'id':1,'title':'Test','requester':'test','media_type':'movie'}
            portal.discord_notify('new_request',[row])

    def test_discord_test_button(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','webhook':hook,'enabled':'on'})
        with patch.object(portal, 'discord_send', return_value=True) as mocked:
            r=self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test'})
        self.assertEqual(r.status_code,302)
        mocked.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
