# -*- coding: utf-8 -*-
import base64

from odoo import http
from odoo.exceptions import ValidationError, UserError
from .main import *

_logger = logging.getLogger(__name__)

import json
from odoo.http import request


def api_response(data, status=200):
    """Helper function to standardize API responses."""
    return request.make_response(
        json.dumps(data),
        headers=[
            ('Content-Type', 'application/json'),
            ('Cache-Control', 'no-store'),
            ('Pragma', 'no-cache')
        ],
        status=status
    )


def decode_base64_image(base64_str):
    """Decodes a Base64 string to binary."""
    try:
        return base64.b64decode(base64_str)
    except Exception as e:
        raise UserError("Invalid image data provided.")


# HTTP controller of REST resources:

class ControllerREST(http.Controller):

    # # Login in Odoo database and get access tokens:
    # @http.route('/api/auth/get_tokens', methods=['HEAD', 'POST', 'OPTIONS'], type='http', auth='none', csrf=False, cors="*")
    # @check_authorization
    # def api_auth_gettokens(self, *args, **kw):
    #     try:
    #         # Convert http data into json:
    #         jdata = json.loads(request.httprequest.stream.read())
    #         username_sent = jdata['username'].lower()
    #         username = request.env['res.users'].get_proper_username(username_sent)
    #         password = jdata['password']
    #         db = jdata['db']
    #         fcm_token = jdata.get('fcm_token')
    #         device_uid = jdata.get('device_uid')
    #
    #         # Empty 'db' or 'username' or 'password:
    #         if not db or not username or not password:
    #             error_description = "Invalid username or password!"
    #             return api_response({"status": True, "intent": False, "description": error_description})
    #
    #         # Login in Demsup database:
    #         try:
    #             request.session.authenticate(db, username, password)
    #             # request.session.ensure_valid()
    #         except Exception as e:
    #             # lets check if user is a third party user
    #             user = request.env['res.users'].search(
    #                 [('login', '=', username)])
    #             if user:
    #                 # Login in Odoo database:
    #                 try:
    #                     request.session.authenticate(db, username, password)
    #                     if fcm_token:
    #                         try:
    #                             user_obj.env.cr.execute("UPDATE res_users SET fcm_token='%s' where login=%s" % (fcm_token, username))
    #                         except Exception as e:
    #                             user_obj.env.cr.rollback()
    #                             pass
    #                     # request.session.ensure_valid()
    #                 except Exception as e:
    #                     # Invalid database:
    #                     error_description = "Invalid 'username' or 'password'!"
    #                     return api_response({"status": True, "intent": False, "description": error_description})
    #             else:
    #                 error_description = "Invalid 'username' or 'password'!"
    #                 return api_response({"status": True, "intent": False, "description": error_description})
    #
    #         uid = request.session.uid
    #
    #         # DemSup login failed:
    #         if not uid:
    #             # lets check if user is a third party user
    #             user = request.env['res.users'].search([('login', '=', username)])
    #             if user:
    #                 # Login in Odoo database:
    #                 try:
    #                     request.session.authenticate(db, username, password)
    #                     uid = request.session.uid
    #                     # request.session.ensure_valid()
    #                 except Exception as e:
    #                     # Invalid database:
    #                     error_description = "Invalid 'username' or 'password'!"
    #                     return api_response({"status": True, "intent": False, "description": error_description})
    #             else:
    #                 error_description = "Invalid email or password!"
    #                 return api_response({"status": True, "intent": False, "description": error_description})
    #
    #         # Generate tokens
    #         access_token = generate_token()
    #         expires_in = access_token_expires_in
    #         refresh_token = generate_token()
    #         refresh_expires_in = refresh_token_expires_in
    #
    #         # Save all tokens in store
    #         token_store.save_all_tokens(
    #             device_uid=device_uid,
    #             access_token=access_token,
    #             expires_in=expires_in,
    #             refresh_token=refresh_token,
    #             refresh_expires_in=refresh_expires_in,
    #             user_id=uid)
    #         last = ''
    #         first = ''
    #         # Successful response:
    #         if uid and request.env.user.name:
    #             names = str(request.env.user.name).split(' ')
    #             if type(names) == list:
    #                 first = str(names[0])
    #                 last = str(names[-1])
    #             else:
    #                 first = str(names[0])
    #
    #         return werkzeug.wrappers.Response(
    #             status=200,
    #             content_type='application/json; charset=utf-8',
    #             headers=[('Cache-Control', 'no-store'),
    #                      ('Pragma', 'no-cache')],
    #             response=json.dumps({
    #                 'uid': uid,
    #                 'name': request.env.user.name if uid else 'null',
    #                 'phone': request.env.user.phone if uid else 'null',
    #                 'login': request.env.user.login if uid else 'null',
    #                 'extras': request.env.user.get_extras() if uid else 'null',
    #                 'access_token': access_token,
    #                 'expires_in': expires_in,
    #                 'status': True,
    #                 'first': first,
    #                 'last': last,
    #                 'refresh_token': refresh_token,
    #                 'refresh_expires_in': refresh_expires_in, }),
    #         )
    #     except Exception as e:
    #         error_message_obj = request.env['byte.error.message']
    #         error_message_obj.env.cr.rollback()
    #         error_message_obj.sudo().create({'name': e,
    #                                          'exception': True,
    #                                          'method': 'api_auth_gettokens',
    #                                          'model': 'auth get token',
    #                                          'meta': "Get Token Attempt"})
    #         error = "Could not Sign In. An error Occurred"
    #         return api_response({"status": True, "intent": False, "description": error})

    # Login in Odoo database and get access tokens:

    @http.route('/api/auth/get_tokens', methods=['HEAD', 'POST', 'OPTIONS'], type='http', auth='none', csrf=False,
                cors="*")
    @check_authorization
    def api_auth_gettokens(self, *args, **kw):
        try:
            # Convert HTTP data into JSON:
            if kw:
                username_sent = kw['username']
                username_sent = username_sent and username_sent.lower().replace(" ", "") or False
                username = username_sent
                password = kw.get('password')
                db = kw.get('db')
                fcm_token = kw.get('fcm_token')
                mode = kw.get('mode')
                device_uid = kw.get('device_uid')
            else:
                # Extract data from the request
                try:
                    jdata = json.loads(request.httprequest.data or "{}")
                except json.JSONDecodeError as je:
                    _logger.error("JSON Decode Error: %s", str(je))
                    return api_response({"status": False, "description": "Invalid JSON payload."}, status=400)

                username_sent = jdata.get('username').lower().replace(" ", "")
                username_sent = username_sent and username_sent.lower().replace(" ", "") or False
                username = username_sent
                password = jdata.get('password')
                db = jdata.get('db')
                fcm_token = jdata.get('fcm_token')
                mode = jdata.get('mode')
                device_uid = jdata.get('device_uid')

            # Check for missing fields
            if not db or not username or not password:
                error_description = "Invalid username or password!"
                return api_response({"status": False, "intent": False, "description": error_description})

            # Authenticate the user in the Odoo database:
            try:
                request.session.authenticate(db, username, password)
            except Exception as e:
                # Check if user is a third-party user
                user = request.env['res.users'].search([('login', '=', username)], limit=1)

                if user:
                    # Try authenticating again
                    try:
                        request.session.authenticate(db, username, password)
                        if fcm_token:
                            user_obj = request.env['res.users']
                            try:
                                user_obj.env.cr.execute(
                                    "UPDATE res_users SET fcm_token=%s WHERE login=%s", (fcm_token, username)
                                )
                            except Exception:
                                user_obj.env.cr.rollback()
                                pass
                    except Exception:
                        error_description = "Invalid username or password!"
                        return api_response({"status": False, "intent": False, "description": error_description})
                else:
                    error_description = "Invalid username or password!"
                    return api_response({"status": False, "intent": False, "description": error_description})

            uid = request.session.uid

            # Authentication failed:
            if not uid:
                error_description = "Invalid email or password!"
                return api_response({"status": False, "intent": False, "description": error_description})

            # Generate tokens
            access_token = generate_token()
            expires_in = access_token_expires_in
            refresh_token = generate_token()
            refresh_expires_in = refresh_token_expires_in

            # Save all tokens in store
            token_store.save_all_tokens(
                device_uid=device_uid,
                access_token=access_token,
                expires_in=expires_in,
                refresh_token=refresh_token,
                refresh_expires_in=refresh_expires_in,
                user_id=uid
            )

            # Get additional user details
            user = request.env['res.users'].sudo().browse(uid)

            # Fetch KYC Applications
            kyc_applications = []
            kyc_records = request.env['qcell_kyc.application'].sudo().search([('partner_id', '=', user.partner_id.id)])
            for kyc in kyc_records:
                kyc_applications.append({
                    'id': kyc.id,
                    'name': kyc.name,
                    'id_type': kyc.id_type or '',  # Assuming id_type is a Char field
                    'id_number': kyc.id_number or '',
                    'id_expiration': kyc.id_expiry_date.isoformat() if kyc.id_expiry_date else None,
                    'current_address': kyc.current_address or '',
                    'permanent_address': kyc.permanent_address or '',
                    'id_document_url': kyc.id_document_url or '',
                    'proof_of_address_url': kyc.proof_of_address_url or '',
                    'selfie_url': kyc.selfie_url or '',
                    'state': kyc.state or '',
                    'verification_notes': kyc.verification_notes or '',
                    'document_upload_date': kyc.document_upload_date.isoformat() if kyc.document_upload_date else None,
                    # Add any other fields you need, with availability checks
                })

            return werkzeug.wrappers.Response(
                status=200,
                content_type='application/json; charset=utf-8',
                headers=[('Cache-Control', 'no-store'), ('Pragma', 'no-cache')],
                response=json.dumps({
                    'uid': uid,
                    'name': user.name if uid else 'null',
                    'phone': user.phone if uid else 'null',
                    'login': user.login if uid else 'null',
                    'extras': user.get_extras() if uid and not mode else 'null',
                    'kyc_applications': kyc_applications,
                    'access_token': access_token,
                    'expires_in': expires_in,
                    'status': True,
                    'refresh_token': refresh_token,
                    'refresh_expires_in': refresh_expires_in,
                })
            )
        except Exception as e:
            _logger.error("Error during get_tokens: %s", str(e))
            error_message_obj = request.env['byte.error.message']
            error_message_obj.env.cr.rollback()
            error_message_obj.sudo().create({
                'name': str(e),
                'exception': True,
                'method': 'api_auth_gettokens',
                'model': 'auth get token',
                'meta': "Get Token Attempt"
            })
            error = "Could not Sign In. An error Occurred"
            return api_response({"status": False, "intent": False, "description": error}) @ http.route(
                '/api/auth/get_tokens', methods=['HEAD', 'POST', 'OPTIONS'], type='http', auth='none', csrf=False,
                cors="*")

    @http.route('/api/auth/get_agent_tokens', methods=['HEAD', 'POST', 'OPTIONS'], type='http', auth='none', csrf=False,
                cors="*")
    @check_authorization
    def api_auth_agentgettokens(self, *args, **kw):
        try:
            # Convert HTTP data into JSON
            if kw:
                username = kw['username'].lower().replace(" ", "")
                password = kw.get('password')
                db = kw.get('db')
                fcm_token = kw.get('fcm_token')
                mode = kw.get('mode')
                device_uid = kw.get('device_uid')
            else:
                try:
                    jdata = json.loads(request.httprequest.data or "{}")
                    username = jdata.get('username').lower().replace(" ", "")
                    password = jdata.get('password')
                    db = jdata.get('db')
                    fcm_token = jdata.get('fcm_token')
                    mode = jdata.get('mode')
                    device_uid = jdata.get('device_uid')
                except json.JSONDecodeError as je:
                    _logger.error("JSON Decode Error: %s", str(je))
                    return api_response({"status": False, "description": "Invalid JSON payload."}, status=400)

            if not db or not username or not password:
                return api_response(
                    {"status": False, "intent": False, "description": "Invalid username or password!"})

            # Authenticate the user in the Odoo database
            try:
                request.session.authenticate(db, username, password)
            except Exception:
                return api_response(
                    {"status": False, "intent": False, "description": "Invalid username or password!"})

            uid = request.session.uid
            if not uid:
                return api_response({"status": False, "intent": False, "description": "Invalid email or password!"})

            user = request.env['res.users'].sudo().browse(uid)

            # Check if user has required permissions
            allowed_groups = [
                'qcell_kyc.group_qcell_kyc_creator',
                'qcell_kyc.group_qcell_kyc_verifier',
                'qcell_kyc.group_qcell_kyc_admin'
            ]
            if not any(user.has_group(group) for group in allowed_groups):
                return api_response({"status": False, "intent": False, "description": "Access denied."}, status=403)

            # Generate tokens
            access_token = generate_token()
            expires_in = access_token_expires_in
            refresh_token = generate_token()
            refresh_expires_in = refresh_token_expires_in
            token_store.save_all_tokens(
                device_uid=device_uid,
                access_token=access_token,
                expires_in=expires_in,
                refresh_token=refresh_token,
                refresh_expires_in=refresh_expires_in,
                user_id=uid
            )

            # Fetch KYC Applications created by the user
            kyc_applications = []
            kyc_records = request.env['qcell_kyc.application'].sudo().search([('create_uid', '=', user.id)])

            # Debug log to check applications found
            _logger.info("Found %s KYC applications for user %s", len(kyc_records), user.name)

            for kyc in kyc_records:
                kyc_applications.append({
                    'id': kyc.id,
                    'name': kyc.name,
                    'state': kyc.state,
                    'verification_notes': kyc.verification_notes,
                })

            return werkzeug.wrappers.Response(
                status=200,
                content_type='application/json; charset=utf-8',
                headers=[('Cache-Control', 'no-store'), ('Pragma', 'no-cache')],
                response=json.dumps({
                    'uid': uid,
                    'name': user.name,
                    'phone': user.phone,
                    'login': user.login,
                    'extras': user.get_extras() if uid and not mode else 'null',
                    'kyc_applications': kyc_applications,
                    'access_token': access_token,
                    'expires_in': expires_in,
                    'status': True,
                    'refresh_token': refresh_token,
                    'refresh_expires_in': refresh_expires_in,
                })
            )
        except Exception as e:
            _logger.error("Error during get_tokens: %s", str(e))
            error_message_obj = request.env['byte.error.message']
            error_message_obj.env.cr.rollback()
            error_message_obj.sudo().create({
                'name': str(e),
                'exception': True,
                'method': 'api_auth_gettokens',
                'model': 'auth get token',
                'meta': "Get Token Attempt"
            })
            return api_response(
                {"status": False, "intent": False, "description": "Could not Sign In. An error occurred"})

    # Refresh access token:
    @http.route('/api/auth/refresh_token', methods=['HEAD', 'POST'], type='http', auth='none', csrf=False)
    @check_authorization
    def api_auth_refreshtoken(self):
        try:
            # Try convert http data into json:
            try:
                jdata = json.loads(request.httprequest.stream.read())
            except:
                jdata = {}
            # Get and check refresh token
            refresh_token = jdata.get('refresh_token')
            if not refresh_token:
                error_description = "No refresh token was provided in request!"
                return api_response({"status": True, "intent": False, "description": error_description})

            # Validate refresh token
            refresh_token_data = token_store.fetch_by_refresh_token(refresh_token)
            if not refresh_token_data:
                return error_response_401__invalid_token()

            old_access_token = refresh_token_data['access_token']
            new_access_token = generate_token()
            uid = refresh_token_data['user_id']

            # Update access (and refresh) token in store
            token_store.update_access_token(
                old_access_token=old_access_token,
                new_access_token=new_access_token,
                expires_in=access_token_expires_in,
                refresh_token=refresh_token,
                user_id=uid)

            last = ''
            first = ''
            user_id = request.env.user.search([('id', '=', uid)])
            if uid and user_id.name:
                names = str(user_id.name).split(' ')
                if type(names) == list:
                    first = str(names[0])
                    last = str(names[-1])
                else:
                    first = str(names[0])

            data = {
                'uid': uid,
                'name': user_id.name if user_id else 'null',
                'phone': user_id.phone if user_id else 'null',
                'login': user_id.login if user_id else 'null',
                'extras': user_id.get_extras() if user_id else 'null',
                'access_token': new_access_token,
                'expires_in': access_token_expires_in,
                'status': True,
                'first': first,
                'last': last,
                'refresh_token': refresh_token,
                'refresh_expires_in': refresh_token_expires_in}

            # Successful response:
            return werkzeug.wrappers.Response(
                status=200,
                content_type='application/json; charset=utf-8',
                headers=[('Cache-Control', 'no-store'),
                         ('Pragma', 'no-cache')],
                response=json.dumps(data),
            )
        except Exception as e:
            error_message_obj = request.env['byte.error.message']
            error_message_obj.sudo().create({'name': e,
                                             'exception': True,
                                             'method': 'api_auth_refreshtoken',
                                             'model': 'auth refresh token',
                                             'meta': "Refresh Token Attempt"})
            error = "Operation not permitted. An error Occurred"
            return api_response({"status": True, "intent": False, "description": error})

    # Delete access tokens from token store:
    @http.route('/api/auth/delete_tokens', methods=['HEAD', 'POST'], type='http', auth='none', csrf=False)
    @check_authorization
    def api_auth_deletetokens(self):
        # Try convert http data into json:
        try:
            jdata = json.loads(request.httprequest.stream.read())
        except:
            jdata = {}
        # Get and check refresh token
        refresh_token = jdata.get('refresh_token')
        if not refresh_token:
            error_description = "No refresh token was provided in request!"
            return api_response({"status": True, "intent": False, "description": error_description})

        token_store.delete_all_tokens_by_refresh_token(refresh_token)

        # Successful response:
        return api_response({})

    @http.route('/api/trigger_password_reset', methods=['HEAD', 'POST', 'OPTIONS'], type='http', auth='none',
                csrf=False,
                cors="*")
    @check_authorization
    def trigger_password_reset(self, *args, **kw):
        try:
            jdata = json.loads(request.httprequest.stream.read())
            login = jdata['login']
            try:
                return api_response(request.env['res.users'].sudo().trigger_password_reset(login))
            except Exception as e:
                error_description = "Could not reset account password."
                return api_response({"status": True, "intent": False, "description": error_description})
        except Exception as e:
            error_message_obj = request.env['byte.error.message']
            error_message_obj.sudo().create({'name': e,
                                             'exception': True,
                                             'method': 'trigger_password_reset',
                                             'model': 'trigger_password_resetn',
                                             'meta': "trigger_password_reset"})
            error = "Operation not permitted. An error Occurred"
            return api_response({"status": True, "intent": False, "description": error})

    @http.route('/api/check_reset_token', methods=['POST', 'OPTIONS'], type='http', auth='none', csrf=False, cors="*")
    @check_authorization
    def check_reset_token(self, *args, **kw):
        try:
            jdata = json.loads(request.httprequest.stream.read())
            token = jdata['token']
            login = jdata['login']
            try:
                res = request.env['res.users'].sudo().check_password_reset_token(login, token)
                return api_response(res)
            except Exception as e:
                error_description = "Could not reset account password."
                return api_response({"status": True, "intent": False, "description": error_description})
        except Exception as e:
            error_message_obj = request.env['byte.error.message']
            error_message_obj.sudo().create({'name': e,
                                             'exception': True,
                                             'method': 'check_reset_token',
                                             'model': 'check_reset_token',
                                             'meta': "check_reset_token"})
            error = "Operation not permitted. An error Occurred"
            return api_response({"status": True, "intent": False, "description": error})

    @http.route('/api/change_password', methods=['POST', 'OPTIONS'], type='http', auth='none', csrf=False, cors="*")
    @check_authorization
    def change_password(self, *args, **kw):
        try:
            jdata = json.loads(request.httprequest.stream.read())
            token = jdata['token']
            login = jdata['login']
            password = jdata['password']
            repeat_password = jdata['repeat_password']
            if password != repeat_password:
                error_description = "Could not reset account password. Passwords do not match"
                return api_response({"status": True, "intent": False, "description": error_description})
            try:
                return api_response(
                    request.env['res.users'].sudo().do_password_reset(login, token, password, repeat_password))
            except Exception as e:
                error_description = "Could not reset account password."
                return api_response({"status": True, "intent": False, "description": error_description})
        except Exception as e:
            error_message_obj = request.env['byte.error.message']
            error_message_obj.sudo().create({'name': e,
                                             'exception': True,
                                             'method': 'change_password',
                                             'model': 'change_password',
                                             'meta': "change_password"})
            error = "Operation not permitted. An error Occurred"
            return api_response({"status": True, "intent": False, "description": error})

    @http.route('/api/change_user_password', methods=['POST', 'OPTIONS'], type='http', auth='none', csrf=False,
                cors="*")
    @check_authorization
    def change_user_password(self, *args, **kw):
        try:
            jdata = json.loads(request.httprequest.stream.read())
            login = jdata['login']
            current_password = jdata['current_password']
            password = jdata['password']
            repeat_password = jdata['repeat_password']
            if password != repeat_password:
                error_description = "Could not reset account password. Passwords do not match"
                return api_response({"status": True, "intent": False, "description": error_description})
            try:
                return api_response(
                    request.env['res.users'].sudo().do_user_password_reset(login, current_password, password,
                                                                           repeat_password))
            except Exception as e:
                error_description = "Could not reset account password."
                return api_response({"status": True, "intent": False, "description": error_description})
        except Exception as e:
            error_message_obj = request.env['byte.error.message']
            error_message_obj.sudo().create({'name': e,
                                             'exception': True,
                                             'method': 'change_password',
                                             'model': 'change_password',
                                             'meta': "change_password"})
            error = "Operation not permitted. An error Occurred"
            return api_response({"status": True, "intent": False, "description": error})

    @http.route('/api/signup', methods=['POST', 'OPTIONS'], type='http', auth='none', csrf=False, cors="*")
    @check_authorization
    def web_auth_signup(self, *args, **kw):
        try:
            # Fetch the default company
            default_company = request.env['res.company'].sudo().search([], limit=1)
            if not default_company:
                return api_response({"status": False, "description": "No default company found."}, status=400)

            # Parse request data
            try:
                jdata = json.loads(request.httprequest.data or "{}")
            except json.JSONDecodeError as je:
                _logger.error("JSON Decode Error: %s", str(je))
                return api_response({"status": False, "description": "Invalid JSON payload."}, status=400)

            # Extract required fields
            name = jdata.get('name')
            login = jdata.get('email', '').lower().strip()
            phone = jdata.get('phone')
            password = jdata.get('password')
            confirm_password = jdata.get('confirm_password')
            user_type = jdata.get('user_type')
            address = jdata.get('address') if user_type in ['new', 'prospective'] else False
            customer_id = jdata.get('customer_id') if user_type == 'existing' else False
            id_number = jdata.get('id_number') if user_type in ['new', 'prospective'] else False
            id_expiration = jdata.get('id_expiration') if user_type in ['new', 'prospective'] else False
            id_type = jdata.get('id_type') if user_type in ['new', 'prospective'] else False
            id_proof_url = jdata.get('id_proof') if user_type in ['new', 'prospective'] else False
            proof_of_address_url = jdata.get('proof_of_address') if user_type == 'new' else False
            selfie_url = jdata.get('selfie')
            device_uid = jdata.get('device_uid')

            # Validate required fields
            if not all([login, password, confirm_password, name, id_type]):
                return api_response({"status": False, "description": "All required fields must be filled."}, status=400)

            if password != confirm_password:
                return api_response({"status": False, "description": "Passwords do not match."}, status=400)

            # Check if email already exists
            existing_user = request.env['res.users'].sudo().search([('login', '=', login)], limit=1)
            if existing_user:
                return api_response({"status": False, "description": "This email is already registered."}, status=400)

            # Ensure image URLs are provided
            if not id_proof_url or not selfie_url:
                return api_response({"status": False, "description": "ID proof and selfie URLs are required."},
                                    status=400)

            # Start a transaction to ensure atomicity
            with request.env.cr.savepoint():
                sign_up_data = {
                    'name': name,
                    'login': login,
                    'password': password,
                    'phone': phone,
                    'company_id': default_company.id,
                    'company_ids': [(6, 0, [default_company.id])],
                }
                new_user = request.env['res.users'].sudo().create(sign_up_data)
                _logger.info("Created new user with ID: %s", new_user.id)

                # Associate existing partner if needed
                if user_type == 'existing' and customer_id:
                    partner = request.env['res.partner'].sudo().search([('id', '=', customer_id)], limit=1)
                    if not partner:
                        raise UserError("Invalid Customer ID provided.")
                    new_user.partner_id = partner.id

                # Update partner with additional details for new or prospective users
                elif user_type in ['new', 'prospective'] and address:
                    new_user.partner_id.street = address

                # Create KYC Application
                kyc_data = {
                    'partner_id': new_user.partner_id.id,
                    'id_type': id_type,
                    'id_number': id_number,
                    'id_document_url': id_proof_url,  # Directly store the URL
                    'proof_of_address_url': proof_of_address_url if proof_of_address_url else None,
                    'selfie_url': selfie_url,  # Directly store the URL
                    'id_expiry_date': id_expiration,
                    'document_upload_date': fields.Datetime.now(),
                    'state': 'draft',
                }
                kyc_application = request.env['qcell_kyc.application'].sudo().create(kyc_data)
                _logger.info("Created KYC Application with name: %s", kyc_application.name)

                response_data = {
                    "uid": new_user.id,
                    "status": True,
                    "description": "User created successfully.",
                    "application_reference": kyc_application.name
                }
                return api_response(response_data, status=200)

        except (ValidationError, UserError) as e:
            _logger.error("Error during signup: %s", str(e))
            return api_response({"status": False, "description": str(e)}, status=400)
        except Exception as e:
            _logger.error("Unexpected error: %s", str(e))
            return api_response({"status": False, "description": "Could not create account. An error occurred."},
                                status=500)

    @http.route('/api/kyc/create', methods=['POST'], type='http', auth='none', csrf=False, cors="*")
    @check_permissions
    def create_kyc_application(self, **kwargs):
        _logger.info("Creating KYC application...")

        # Check if the user has the necessary permissions
        allowed_groups = [
            'qcell_kyc.group_qcell_kyc_creator',
            'qcell_kyc.group_qcell_kyc_verifier',
            'qcell_kyc.group_qcell_kyc_admin'
        ]

        if not any(request.env.user.has_group(group) for group in allowed_groups):
            return request.make_response(json.dumps({
                'status': False,
                'message': 'You do not have the permissions to perform this action.'
            }), headers={'Content-Type': 'application/json'}, status=403)

        # Parse the request data
        try:
            data = json.loads(request.httprequest.data)
        except json.JSONDecodeError:
            return request.make_response(json.dumps({
                'status': False,
                'message': 'Invalid JSON data'
            }), headers={'Content-Type': 'application/json'}, status=400)

        # Extract required fields for client (res.partner) creation
        name = data.get('name')
        login = data.get('login')  # Client's email or unique identifier
        phone = data.get('phone')
        company_id = request.env.user.company_id.id or request.env['res.company'].sudo().search([], limit=1).id

        # Ensure required fields are provided
        if not name or not login or not phone:
            return request.make_response(json.dumps({
                'status': False,
                'message': 'Required fields for client creation are missing.'
            }), headers={'Content-Type': 'application/json'}, status=400)

        # Extract KYC-specific fields from the data
        id_type = data.get('id_type')
        id_number = data.get('id_number')
        id_expiry_date = data.get('id_expiry_date')
        id_document_url = data.get('id_document_url')
        proof_of_address_url = data.get('proof_of_address_url')
        selfie_url = data.get('selfie_url')
        current_address = data.get('current_address')
        permanent_address = data.get('permanent_address')
        application_reference = data.get('application_reference')

        # Validate required fields for KYC application
        if not id_type or not id_number:
            return request.make_response(json.dumps({
                'status': False,
                'message': 'Required fields for KYC application are missing.'
            }), headers={'Content-Type': 'application/json'}, status=400)

        # Perform all uniqueness checks before any creation
        # Uniqueness checks for email and phone
        existing_partner_email = request.env['res.partner'].sudo().search([('email', '=', login)], limit=1)
        if existing_partner_email:
            return request.make_response(json.dumps({
                'status': False,
                'message': f"A client with email '{login}' already exists."
            }), headers={'Content-Type': 'application/json'}, status=400)

        existing_partner_phone = request.env['res.partner'].sudo().search([('phone', '=', phone)], limit=1)
        if existing_partner_phone:
            return request.make_response(json.dumps({
                'status': False,
                'message': f"A client with phone number '{phone}' already exists."
            }), headers={'Content-Type': 'application/json'}, status=400)

        # Uniqueness checks for id_number and application_reference
        existing_kyc_id_number = request.env['qcell_kyc.application'].sudo().search([('id_number', '=', id_number)],
                                                                                    limit=1)
        if existing_kyc_id_number:
            return request.make_response(json.dumps({
                'status': False,
                'message': f"A KYC application with ID number '{id_number}' already exists."
            }), headers={'Content-Type': 'application/json'}, status=400)

        if application_reference:
            existing_kyc_reference = request.env['qcell_kyc.application'].sudo().search(
                [('name', '=', application_reference)], limit=1)
            if existing_kyc_reference:
                return request.make_response(json.dumps({
                    'status': False,
                    'message': f"A KYC application with reference '{application_reference}' already exists."
                }), headers={'Content-Type': 'application/json'}, status=400)
        else:
            # Generate a unique application reference if not provided
            application_reference = self._generate_unique_application_reference()

        # All checks passed, proceed to create partner and application
        try:
            # Begin a new transaction
            with request.env.cr.savepoint():
                # Create a new partner for the client
                client_partner = request.env['res.partner'].sudo().create({
                    'name': name,
                    'email': login,
                    'phone': phone,
                    'company_id': company_id,
                })

                # Create the KYC application for the client
                kyc_application = request.env['qcell_kyc.application'].sudo().create({
                    'name': application_reference,
                    'partner_id': client_partner.id,
                    'id_type': id_type,
                    'id_number': id_number,
                    'id_expiry_date': id_expiry_date,
                    'id_document_url': id_document_url,
                    'proof_of_address_url': proof_of_address_url,
                    'selfie_url': selfie_url,
                    'current_address': current_address,
                    'permanent_address': permanent_address,
                    'state': 'draft',
                    'document_upload_date': fields.Datetime.now(),
                })

            return request.make_response(json.dumps({
                'status': True,
                'message': 'KYC application created successfully for the client.',
                'application_id': kyc_application.id,
                'client_partner_id': client_partner.id
            }), headers={'Content-Type': 'application/json'}, status=200)

        except Exception as e:
            request.env.cr.rollback()  # Rollback transaction in case of error
            _logger.error("Error creating KYC application: %s", e)
            return request.make_response(json.dumps({
                'status': False,
                'message': f'An error occurred: {str(e)}'
            }), headers={'Content-Type': 'application/json'}, status=500)

    def _generate_unique_application_reference(self):
        # Implement logic to generate a unique application reference
        # This can be based on a sequence or any other method
        sequence = request.env['ir.sequence'].sudo().next_by_code('qcell_kyc.application') or '/'
        return sequence
