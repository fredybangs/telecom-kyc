import binascii
import hashlib
import os

from odoo import models, fields, api, tools, _
from odoo.exceptions import ValidationError
from dateutil import relativedelta
import logging
import random
from datetime import datetime
from odoo.exceptions import UserError
from odoo.addons.auth_signup.models.res_partner import SignupError, now

try:
    import simplejson as json
except ImportError:
    import json
_logger = logging.getLogger(__name__)

months = {1: 'january', 2: 'february',
          3: 'march', 4: 'april',
          5: 'may', 6: 'june',
          7: 'july', 8: 'august',
          9: 'september', 10: 'october',
          11: 'november', 12: 'december'}


def random_pin():
    # the token has an entropy of about 120 bits (6 bits/char * 20 chars)
    chars = '0123456789'
    return ''.join(random.SystemRandom().choice(chars) for i in range(6))


class ResUsers(models.Model):
    _inherit = 'res.users'

    app_user = fields.Boolean(default=False, string='App User')
    activation_date = fields.Datetime(string="Account Activated on", readonly=True)

    fcm_user_token = fields.Char(readonly=True)
    fcm_token = fields.Char(string='FCM Token')

    # Device Registration Info
    device_uid = fields.Char(string='Device UID', readonly=True)
    device_name = fields.Char(string='Device Name', readonly=True)
    device_os = fields.Char(string='Device OS', readonly=True)
    device_type = fields.Char(string='Device Type', readonly=True)
    device_os_version = fields.Char(string='Device OS Version', readonly=True)
    device_total_memory = fields.Char(string='Device Total Memory', readonly=True)
    device_carrier = fields.Char(string='Device Carrier', readonly=True)
    device_phone_no = fields.Char(string='Device Phone #', readonly=True)
    device_has_notch = fields.Boolean(string='Device has notch', readonly=True)
    device_manufacturer = fields.Char(string='Device Manufacturer', readonly=True)
    password_changed = fields.Boolean(default=False)
    last_seen = fields.Datetime(string='Last seen')

    def get_proper_username(self, username):
        if '@' in username:
            return username
        return False

    def get_extras(self):
        return {}

    def send_notification(self, notification_type, subject, body):
        if notification_type == 'email':
            mail_object = self.env['mail.mail']
            subject = subject
            body = body
            default_email = self.login

            email = mail_object.create({'subject': subject,
                                        'email_from': self.company_id.email,
                                        'email_to': default_email and default_email,
                                        'body_html': body})
            email.send()

    def change_user_password(self, user, old_password, new_password):
        if self.id != user:
            return {"status": True, "description": 'Access denied'}
        try:
            self.change_password(old_password, new_password)
            return {'status': True, 'intent': True, 'description': "Password Changed Successfully"}
        except Exception as e:
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'create_user',
                                          'model': str(self),
                                          'meta': "Parameters %s  Parameter value %s, "
                                                  "Parameters %s  Parameter value %s, "
                                                  "Parameters %s  Parameter value %s, " %
                                                  ("user", user, "old_password", old_password, "new_password",
                                                   new_password)})
            except Exception as e:
                pass
            error = e.message
            if str(e.message) == 'Access denied':
                error = "Old password is Incorrect"
            return {"status": True, "intent": False, "description": error}

    @api.model
    def change_password(self, old_passwd, new_passwd):
        """Change current user password. Old password must be provided explicitly
        to prevent hijacking an existing user session, or for cases where the cleartext
        password is not used to authenticate requests.

        :return: True
        :raise: odoo.exceptions.AccessDenied when old password is wrong
        :raise: odoo.exceptions.UserError when new password is not set or empty
        """
        self.check(self._cr.dbname, self.id, old_passwd)
        if new_passwd:
            # use self.env.user here, because it has uid=SUPERUSER_ID
            return self.write({'password': new_passwd, 'password_changed': True})
        raise fields.UserError("Setting empty passwords is not allowed for security reasons!")

    def update_fcm_token(self, user, fcm_token):
        if self.id != user:
            return {"status": True, "intent": False, "description": 'Access denied'}
        try:
            self.write({'fcm_token': fcm_token})
            return {'status': True, 'intent': True, 'description': 'FCM Token Updated'}
        except Exception as e:
            error = "Error Occurred"
            return {"status": True, "intent": False, "description": error}

    """
            curl -X POST \
          https://fcm.googleapis.com/fcm/send \
          -H 'Authorization: key=AAAACGkU59w:APA91bFxutpiRDClxX_4mRj1SBon3yA1FZqfkO-3TKkDFGCEMjKpq43quiUd0-qqkVbJrtB9MvVQo2gVssxunZhMQoWE8it7AM98VyA8_hw2lNlJVibqe_O3qtlVHRLhgZvvp1-6N8ub' \
          -H 'Content-Type: application/json' \
          -H 'Host: fcm.googleapis.com' \
          -d '{
         "to" : "fCygXL1wR1u7aX99nFVgFZ:APA91bHCVp5z87VbVHhMXoFQwEDrXQzAt4o-MOBkUSttiINNoZrjwjgoUnchNBo8JRX9sXAiv04N6RhGnt1UwWfMVqvaGGYvbYRMwfuKGr0OGG_Bx0g_ygBTIB6oJNn1sD3eC4jtsUrW",
         "data" : {
             "body" : "Body of Your Notification in Data",
             "title": "Title of Your Notification in Title",
             "key_1" : "Value 1",
             "key_2" : "Value 1"
         }
        }'

    """

    def test_notify(self):
        for rec in self:
            rec.send_fcm_notification("Hello", "Hello Test %s" % rec.name)

    def trigger_password_reset(self, login):
        try:
            user = self.search([('login', '=', login)])
            if not user:
                error = "Could not reset Password. An error Occurred. Try Again"
                return {"status": True, "intent": False, "description": error}
            activation_obj = self.env['email.activation']

            # Lets delete existing pasword resets objects
            existing = activation_obj.search([('user_id', '=', user.id), ('ttype', '=', 'password')])
            for item in existing:
                item.unlink()
            password_reset_data = {'user_id': user.id,
                                   'auto': True,
                                   'ttype': 'password'}

            res = activation_obj.create(password_reset_data)
            return res.send_password_reset_email()

        except Exception as e:
            self.env.cr.rollback()
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'trigger_password_reset',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s" % (
                                              "login", login)})
            except Exception as e:
                pass
        error = "Could not reset Password. An error Occurred. Try Again"
        return {"status": True, "intent": False, "description": error}

    def self_trigger_password_reset(self):
        try:
            user = self
            login = self.login
            if not user:
                error = "Could not reset Password. An error Occurred. Try Again"
                return {"status": True, "intent": False, "description": error}
            activation_obj = self.env['email.activation']

            # Lets delete existing pasword resets objects
            existing = activation_obj.search([('user_id', '=', user.id), ('ttype', '=', 'password')])
            for item in existing:
                item.unlink()
            password_reset_data = {'user_id': user.id,
                                   'auto': True,
                                   'ttype': 'password'}

            res = activation_obj.create(password_reset_data)
            return res.send_password_reset_email()

        except Exception as e:
            self.env.cr.rollback()
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'trigger_password_reset',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s" % (
                                              "login", login)})
            except Exception as e:
                pass
        error = "Could not reset Password. An error Occurred. Try Again"
        return {"status": True, "intent": False, "description": error}

    def check_password_reset_token(self, login, token):
        try:
            user = self.search([('login', '=', login)])
            if not user:
                error = "Could not reset password. An error occurred. Try Again"
                return {"status": True, "intent": False, "description": error}
            activation_obj = self.env['email.activation']

            res = activation_obj.search([('token', '=', token)])
            if res.user_id.id != user.id:
                error = "An Error Occurred. Please try resetting password again"
                return {"status": True, "intent": False, "description": error}
            if not res.auto_user_check_token():
                return {"status": True, "intent": False,
                        "description": 'Token has expired. Please try resetting password again'}
            if res.token and res.token == token:
                return {'status': True, 'intent': True, 'description': 'Token Valid'}
            else:
                error = "Invalid Token, Try Again"
                return {"status": True, "intent": False, "description": error}

        except Exception as e:
            self.env.cr.rollback()
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'check_password_reset_token',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s, Parameter %s  Parameter value %s" % (
                                              "login", login, 'token', token)})
            except Exception as e:
                pass
        error = "Could not reset Password. An error Occurred. Try Again"
        return {"status": True, "intent": False, "description": error}

    def reset_password(self, password):
        result = self.write({'password': password})
        return result

    def do_password_reset(self, login, token, password, repeat_password):
        if password != repeat_password:
            error = "Passwords do not match. Try Again"
            return {"status": True, "intent": False, "description": error}
        try:
            res = self.check_password_reset_token(login, token)
            if res['status'] and res['intent']:
                user = self.search([('login', '=', login)], limit=1)
                if user.reset_password(password):
                    activation_obj = self.env['email.activation']

                    # Lets delete existing pasword resets objects
                    existing = activation_obj.search([('user_id', '=', user.id), ('ttype', '=', 'password')])
                    for item in existing:
                        item.unlink()
                    return {'status': True, 'intent': True, 'description': "Password Reset Successfully"}
            else:
                error = "Could not reset Password. An error Occurred. Try Again"
                return {"status": True, "intent": False, "description": error}

        except Exception as e:
            self.env.cr.rollback()
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'do_password_reset',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s, "
                                                  "Parameter %s  Parameter value %s,"
                                                  "Parameter %s  Parameter value %s,"
                                                  "Parameter %s  Parameter value %s," % (
                                                      "login", login, 'token', token, 'password', password,
                                                      'repeat_password', repeat_password)})
            except Exception as e:
                pass
        error = "Could not reset Password. An error Occurred. Try Again"
        return {"status": True, "intent": False, "description": error}

    def do_user_password_reset(self, login, current_password, password, repeat_password):
        if password != repeat_password:
            error = "Passwords do not match. Try Again"
            return {"status": True, "intent": False, "description": error}
        try:
            user = self.search([('login', '=', login)], limit=1)
            if user.change_password(current_password, password):
                return {'status': True, 'intent': True, 'description': "Password Reset Successfully"}
            else:
                error = "Could not reset Password. An error Occurred. Try Again"
                return {"status": True, "intent": False, "description": error}
        except Exception as e:
            self.env.cr.rollback()
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'do_password_reset',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s, "
                                                  "Parameter %s  Parameter value %s,"
                                                  "Parameter %s  Parameter value %s,"
                                                  "Parameter %s  Parameter value %s," % (
                                                      "login", login, 'token', login, 'password', password,
                                                      'repeat_password', repeat_password)})
            except Exception as e:
                pass
        error = "Could not reset Password. An error Occurred. Try Again"
        return {"status": True, "intent": False, "description": error}

    def update_profile(self, data):
        # TODO delete access token from redis if email is changed
        for rec in self:
            for item in data:
                if item not in ['name', 'phone', 'photo_url', 'login']:
                    error = "Could not update profile. An error Occurred. Try Again"
                    return {"status": True, "intent": False, "description": error}
            if data:
                rec.write(data)
                return {'status': True, 'intent': True, 'description': "Profile Updated Successfully"}
            return {'status': True, 'intent': False, 'description': "Profile not Updated "}

    def action_reset_password(self):
        """ create signup token for each user, and send their signup url by email """
        if self.env.context.get('install_mode', False):
            return
        if self.filtered(lambda user: not user.active):
            raise UserError(_("You cannot perform this action on an archived user."))
        # prepare reset password signup
        create_mode = bool(self.env.context.get('create_user'))

        # no time limit for initial invitation, only for reset password
        expiration = False if create_mode else now(days=+1)

        self.mapped('partner_id').signup_prepare(signup_type="reset", expiration=expiration)

        # send email to users with their signup url
        template = False
        if create_mode:
            try:
                template = self.env.ref('demsup.welcome_email', raise_if_not_found=False)
            except ValueError:
                pass
        if not template:
            template = self.env.ref('byte_core.reset_password_email')
        assert template._name == 'mail.template'

        email_values = {
            'email_cc': False,
            'auto_delete': True,
            'recipient_ids': [],
            'partner_ids': [],
            'scheduled_date': False,
        }

        for user in self:
            if not user.email:
                raise UserError(_("Cannot send email: user %s has no email address.", user.name))
            email_values['email_to'] = user.email
            # TDE FIXME: make this template technical (qweb)
            with self.env.cr.savepoint():
                force_send = not(self.env.context.get('import_file', False))
                template.send_mail(user.id, force_send=force_send, raise_exception=True, email_values=email_values)
            _logger.info("Password reset email sent for user <%s> to <%s>", user.login, user.email)



