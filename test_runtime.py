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
        headers = {**self.headers, **kwargs.pop('headers', {})}
        return self.client.open(path, method=method, base_url=self.url, headers=headers, **kwargs)

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

    def test_removed_media_can_be_requested_again(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title,status) VALUES (?,?,?,?,?)",
                      ('plex:222','801237','movie','Old copy','removed'))
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:222','801237','movie','New copy'))

    def test_refresh_confirms_absence_in_both_services(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title,status) VALUES (?,?,?,?,?)",
                      ('plex:222','801238','movie','Removed title','approved'))
        with patch.object(portal, 'plex_get', return_value={'Metadata': []}), \
             patch.object(portal, 'has_membership', return_value=False):
            checked, removed = portal.sync_removed_requests(force=True)
        self.assertEqual((checked, removed), (1, 1))
        with portal.conn() as c:
            self.assertEqual(c.execute("SELECT status FROM requests WHERE plex_id='801238'").fetchone()[0], 'removed')

    def test_refresh_keeps_approved_if_still_in_plex(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title,status) VALUES (?,?,?,?,?)",
                      ('plex:222','801239','movie','Still available','approved'))
        with patch.object(portal, 'plex_get', return_value={'Metadata': [{'ratingKey':'801239','type':'movie'}]}), \
             patch.object(portal, 'has_membership') as member:
            checked, removed = portal.sync_removed_requests(force=True)
        self.assertEqual((checked, removed), (1, 0))
        member.assert_not_called()

    def test_refresh_preserves_approved_on_collection_error(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title,status) VALUES (?,?,?,?,?)",
                      ('plex:222','801240','movie','Unknown deletion','approved'))
        with patch.object(portal, 'plex_get', return_value={'Metadata': []}), \
             patch.object(portal, 'has_membership', side_effect=ValueError('upstream')):
            _, removed = portal.sync_removed_requests(force=True)
        self.assertEqual(removed, 0)
        with portal.conn() as c:
            self.assertEqual(c.execute("SELECT status FROM requests WHERE plex_id='801240'").fetchone()[0], 'approved')

    def test_refresh_requires_admin_and_csrf(self):
        self.logged_in('222')
        self.assertEqual(self.req('/admin/requests/refresh', 'POST',
                                  data={'csrf': 'csrf-test'}).status_code, 403)
        self.logged_in('111')
        self.assertEqual(self.req('/admin/requests/refresh', 'POST').status_code, 403)
        with patch.object(portal, 'sync_removed_requests', return_value=(0, 0)):
            self.assertEqual(self.req('/admin/requests/refresh', 'POST',
                                      data={'csrf': 'csrf-test'}).status_code, 302)

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
        page = self.req('/requests?view=all')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Shared User Request', page.data)
        self.assertIn(b'Approve', page.data)
        with patch.object(portal, 'plex_libraries', return_value=[]):
            dashboard = self.req('/')
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b'/requests', dashboard.data)
        self.assertIn(b'PLEX SERVER ADMINISTRATION', dashboard.data)

    def test_requester_cannot_read_all_requests(self):
        with portal.conn() as c:
            c.execute("INSERT INTO requests (requester,plex_id,media_type,title) VALUES (?,?,?,?)",
                      ('plex:333','908902','movie','Private Request'))
        self.logged_in('222')
        self.assertEqual(self.req('/admin/requests').status_code, 403)
        self.assertEqual(self.req('/requests?view=all').status_code, 403)
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
        first = self.req('/requests?view=all')
        second = self.req('/requests?view=all&page=2')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertIn(b'Next', first.data)
        self.assertNotIn(b'History item 0', first.data)
        self.assertIn(b'History item 0', second.data)
        self.assertEqual(self.req('/requests?view=all&page=invalid').status_code, 400)

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
        response = self.req('/requests')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Mine Visible', response.data)
        self.assertNotIn(b'Other Hidden', response.data)

    def test_requests_tabs_only_visible_to_admin(self):
        self.logged_in('111')
        admin = self.req('/requests')
        self.assertEqual(admin.status_code, 200)
        self.assertIn(b'All Requests', admin.data)
        self.assertIn(b'My Requests', admin.data)
        self.assertIn(b'view=mine', admin.data)
        self.logged_in('222')
        regular = self.req('/requests')
        self.assertEqual(regular.status_code, 200)
        self.assertNotIn(b'view=all', regular.data)
        self.assertNotIn(b'class="request-tabs"', regular.data)
        self.assertEqual(self.req('/requests?view=all').status_code, 403)

    def test_one_click_login_redirects_directly_to_plex(self):
        login = self.req('/login')
        self.assertIn(b'Sign in with Plex', login.data)
        self.assertIn(b'/static/login.js', login.data)
        self.assertEqual(self.req('/auth/plex/start').status_code, 405)
        with patch.object(portal, 'plex_cloud', return_value={'id': 123456, 'code': 'sufficiently-long-code'}):
            response = self.req('/auth/plex/start', 'POST',
                                data={'csrf': self.csrf()}, headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['url'].startswith('https://app.plex.tv/auth#?'))
        self.assertIn('forwardUrl=', response.json['url'])

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
            c.execute('UPDATE discord_test_limits SET last_attempt=0 WHERE id=1')

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

    def test_first_webhook_save_auto_enables_and_explicit_disable_persists(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','webhook':hook})
        self.assertEqual(portal.discord_config()['enabled'], 1)
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test'})
        self.assertEqual(portal.discord_config()['enabled'], 0)
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','new_request':'on'})
        self.assertEqual(portal.discord_config()['enabled'], 0)
        new_hook='https://discord.com/api/webhooks/123456789012345678/'+'b'*60
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','webhook':new_hook})
        self.assertEqual(portal.discord_config()['enabled'], 1)
        self.req('/admin/discord/remove',method='POST',data={'csrf':'csrf-test'})
        self.assertEqual(portal.discord_config()['enabled'], 0)

    def test_unsaved_webhook_can_be_tested_without_saving(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            response=self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test','webhook':hook},
                              headers={'Accept':'application/json'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['ok'])
        self.assertEqual(sent.call_args.args[0], hook)
        self.assertIsNone(portal.discord_config()['webhook_cipher'])

    def test_discord_ajax_errors_are_json_and_cooldown_enforced(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        headers={'Accept':'application/json'}
        failed=self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test','webhook':'https://invalid.test/anything'},
                        headers=headers)
        self.assertEqual(failed.status_code,400)
        self.assertFalse(failed.json['ok'])
        with patch.object(portal,'discord_send',return_value=True) as sent:
            ok=self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test','webhook':hook},headers=headers)
            cooldown=self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test','webhook':hook},headers=headers)
        self.assertEqual(ok.status_code,200)
        self.assertEqual(cooldown.status_code,429)
        sent.assert_called_once()
        self.assertFalse(cooldown.json['ok'])

    def test_discord_script_served_with_strict_csp(self):
        self.logged_in('111')
        response=self.req('/admin/discord')
        self.assertIn(b'/static/discord.js', response.data)
        self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
        self.assertNotIn("'unsafe-inline'", response.headers['Content-Security-Policy'].split("script-src ")[1].split(";")[0])

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


    def test_discord_redirect_is_not_success(self):
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        for status, expected in [(204,True),(200,True),(302,False),(307,False),
                                 (400,False),(429,False),(500,False)]:
            reply=MagicMock(status_code=status)
            with patch.object(portal.discord_http, 'post', return_value=reply) as posted:
                self.assertEqual(portal.discord_send(hook, 'test'), expected)
            self.assertFalse(posted.call_args.kwargs['allow_redirects'])
            self.assertEqual(posted.call_args.kwargs['timeout'], (1,2))

    def test_discord_http_ignores_proxy_environment(self):
        self.assertFalse(portal.discord_http.trust_env)
        self.assertEqual(portal.discord_http.max_redirects, 0)

    def test_discord_test_button_rate_limited(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test','webhook':hook})
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            self.assertEqual(self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test'}).status_code,302)
            self.assertEqual(self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test'}).status_code,302)
            sent.assert_called_once()
        with portal.conn() as c:
            c.execute('UPDATE discord_test_limits SET last_attempt=0 WHERE id=1')
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            self.req('/admin/discord/test',method='POST',data={'csrf':'csrf-test'})
            sent.assert_called_once()

    def test_discord_invalid_saved_url_never_sent(self):
        with patch.object(portal.discord_http, 'post') as posted:
            self.assertFalse(portal.discord_send('https://evil.test/unsafe','test'))
            posted.assert_not_called()

    def test_discord_no_mentions_and_sanitized_message(self):
        self.logged_in('111')
        hook='https://discord.com/api/webhooks/123456789012345678/'+'a'*60
        self.req('/admin/discord/save',method='POST',data={'csrf':'csrf-test',
                  'webhook':hook,'enabled':'on','new_request':'on'})
        row={'id':1,'title':'@everyone\nFake approval', 'requester':'plex:222','media_type':'movie'}
        with patch.object(portal.discord_http, 'post', return_value=MagicMock(status_code=204)) as posted:
            portal.discord_notify('new_request',[row])
        body=posted.call_args.kwargs['json']
        self.assertEqual(body['allowed_mentions'], {'parse': []})
        self.assertNotIn('@everyone', body['embeds'][0]['description'])
        self.assertNotIn('\n', body['embeds'][0]['description'])


    def _configure_discord(self, **flags):
        """Enable a fake webhook without ever making a network request."""
        self.logged_in('111')
        form = {'csrf': 'csrf-test', 'enabled': 'on',
                'webhook': 'https://discord.com/api/webhooks/123456789012345678/' + 'a' * 60}
        form.update({key: 'on' for key, on in flags.items() if on})
        response = self.req('/admin/discord/save', method='POST', data=form)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(portal.discord_config()['enabled'], 1)

    def _request_row(self, plex_id='87654321', status='pending'):
        with portal.conn() as c:
            c.execute('INSERT INTO requests (requester, plex_id, media_type, title, status) '
                      'VALUES (?,?,?,?,?)', ('plex:222', plex_id, 'movie', 'Test Movie', status))
            return c.execute('SELECT id FROM requests WHERE plex_id=?', (plex_id,)).fetchone()[0]

    def test_discord_request_lifecycle_notifications(self):
        """Submitting, approving, rejecting, and review each use the correct event."""
        self._configure_discord(new_request=True, approved=True, rejected=True, review=True)
        media = {'id': '87654322', 'title': 'Test Movie', 'type': 'movie', 'section_id': '1'}
        self.logged_in('222')
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req('/request', 'POST', data={'csrf': 'csrf-test', 'plex_id': media['id']})
        self.assertEqual(response.status_code, 302)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'New removal request')
        with portal.conn() as c:
            request_id = c.execute('SELECT id FROM requests WHERE plex_id=?', (media['id'],)).fetchone()[0]
        self.logged_in('111')
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'check_collection'), \
             patch.object(portal, 'has_membership', side_effect=[False, True]), \
             patch.object(portal, 'service_json', return_value={}) as upstream, \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req(f'/decide/{request_id}', 'POST', data={'csrf': 'csrf-test', 'decision': 'approve'})
        self.assertEqual(response.status_code, 302)
        upstream.assert_called_once()
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'Request approved')
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE id=?', (request_id,)).fetchone()[0], 'approved')

        request_id = self._request_row('87654323')
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req(f'/decide/{request_id}', 'POST', data={'csrf': 'csrf-test', 'decision': 'reject'})
        self.assertEqual(response.status_code, 302)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'Request rejected')
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE id=?', (request_id,)).fetchone()[0], 'rejected')

        request_id = self._request_row('87654324')
        uncertain = {**media, 'id': '87654324'}
        with patch.object(portal, 'plex_item', return_value=uncertain), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'check_collection'), \
             patch.object(portal, 'has_membership', return_value=False), \
             patch.object(portal, 'service_json', side_effect=portal.requests.Timeout('ambiguous')) as upstream, \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req(f'/decide/{request_id}', 'POST', data={'csrf': 'csrf-test', 'decision': 'approve'})
        self.assertEqual(response.status_code, 302)
        upstream.assert_called_once()
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'Request needs review')
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE id=?', (request_id,)).fetchone()[0], 'review')

    def test_discord_bulk_submission_aggregates_notifications(self):
        self._configure_discord(new_request=True)
        self.logged_in('222')
        items = {'87654331': {'id': '87654331', 'type': 'movie', 'title': 'Movie A', 'section_id': '1'},
                 '87654332': {'id': '87654332', 'type': 'movie', 'title': 'Movie B', 'section_id': '1'}}
        with patch.object(portal, 'plex_item', side_effect=lambda item, **kw: items[item]), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req('/request/bulk', 'POST', data={'csrf': 'csrf-test', 'plex_ids': list(items)})
        self.assertEqual(response.status_code, 302)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'New removal request')
        self.assertIn('Movie A', sent.call_args.args[1])
        self.assertIn('Movie B', sent.call_args.args[1])
        with portal.conn() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM requests WHERE plex_id IN ('87654331','87654332')").fetchone()[0], 2)

    def test_discord_event_toggles_block_selected_notifications(self):
        self._configure_discord(new_request=False, approved=True, rejected=False, review=False)
        row = {'id': 1, 'title': 'Film', 'requester': 'plex:222', 'media_type': 'movie'}
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            for event in ('new_request', 'rejected', 'review'):
                portal.discord_notify(event, [row])
            sent.assert_not_called()
            portal.discord_notify('approved', [row])
            sent.assert_called_once()
            self.assertEqual(sent.call_args.kwargs['title'], 'Request approved')
        with portal.conn() as c:
            c.execute('UPDATE discord_settings SET enabled=0 WHERE id=1')
        with patch.object(portal, 'discord_send', return_value=True) as sent:
            portal.discord_notify('approved', [row])
            sent.assert_not_called()

    def test_discord_toggle_blocks_real_request_notification(self):
        self._configure_discord(new_request=False)
        self.logged_in('222')
        media = {'id': '87654335', 'title': 'Silent Film', 'type': 'movie', 'section_id': '1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req('/request', 'POST', data={'csrf': 'csrf-test', 'plex_id': media['id']})
        self.assertEqual(response.status_code, 302)
        sent.assert_not_called()
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE plex_id=?', (media['id'],)).fetchone()[0], 'pending')

    def test_discord_reconcile_notifies_only_on_confirmed_membership(self):
        self._configure_discord(approved=True)
        req_id = self._request_row('87654336', 'review')
        media = {'id': '87654336', 'title': 'Test Movie', 'type': 'movie', 'section_id': '1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'has_membership', return_value=False), \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req(f'/admin/reconcile/{req_id}', 'POST', data={'csrf': 'csrf-test'})
        self.assertEqual(response.status_code, 302)
        sent.assert_not_called()
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'has_membership', return_value=True), \
             patch.object(portal, 'discord_send', return_value=True) as sent:
            response = self.req(f'/admin/reconcile/{req_id}', 'POST', data={'csrf': 'csrf-test'})
        self.assertEqual(response.status_code, 302)
        sent.assert_called_once()
        self.assertEqual(sent.call_args.kwargs['title'], 'Request approved')
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE id=?', (req_id,)).fetchone()[0], 'approved')

    def test_discord_unconfigured_or_failed_delivery_is_nonblocking(self):
        self.logged_in('222')
        media = {'id': '87654337', 'title': 'Test Film', 'type': 'movie', 'section_id': '1'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'discord_send', side_effect=AssertionError('must be disabled')):
            response = self.req('/request', 'POST', data={'csrf': 'csrf-test', 'plex_id': media['id']})
        self.assertEqual(response.status_code, 302)
        self._configure_discord(new_request=True)
        self.logged_in('222')
        media = {**media, 'id': '87654338'}
        with patch.object(portal, 'plex_item', return_value=media), \
             patch.object(portal, 'collection_for_item', return_value=1), \
             patch.object(portal, 'discord_send', side_effect=portal.requests.Timeout('discord')):
            response = self.req('/request', 'POST', data={'csrf': 'csrf-test', 'plex_id': media['id']})
        self.assertEqual(response.status_code, 302)
        with portal.conn() as c:
            self.assertEqual(c.execute('SELECT status FROM requests WHERE plex_id=?', (media['id'],)).fetchone()[0], 'pending')

if __name__ == '__main__':
    unittest.main(verbosity=2)
