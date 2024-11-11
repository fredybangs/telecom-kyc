from odoo import api, models, fields
from datetime import datetime
from datetime import timedelta
import random


def random_token():
    # the token has an entropy of about 120 bits (6 bits/char * 20 chars)
    chars = '0123456789'
    return ''.join(random.SystemRandom().choice(chars) for i in range(6))


class EmailActivation(models.Model):
    _name = 'email.activation'
    _rec_name = 'token'
    _description = "Activation Password Rest Token Objects"
    ttype = fields.Selection([('password', 'Password Token'), ('activation', 'Account Activation Token')],
                             required=True, readonly=True)
    user_id = fields.Many2one(comodel_name='res.users', string='User',
                              ondelete='cascade',
                              required=True, readonly=True)
    token = fields.Char(readonly=True)
    date = fields.Datetime(string="Activation Date", default=datetime.now(), readonly=True)
    expiry_date = fields.Datetime(readonly=True)
    reset_attempt = fields.Integer(default=0, readonly=True)
    auto = fields.Boolean(default=False, string="Auto Generated", readonly=True)
    active = fields.Boolean(default=True)

    @api.model
    def create(self, vals):
        expiry_minutes = self.env.user.company_id.token_time_out
        expiry_date = fields.Datetime.to_string(datetime.today() + timedelta(minutes=expiry_minutes))
        vals['expiry_date'] = expiry_date
        vals['token'] = random_token()
        token = super(EmailActivation, self).create(vals)
        expiry_minutes = token.user_id.company_id.token_time_out
        expiry_date = fields.Datetime.to_string(datetime.today() + timedelta(minutes=expiry_minutes))
        token.write({'expiry_date': expiry_date})
        if vals['ttype'] == 'activation':
            token.send_activation_email(called=False)
        try:
            existing_tokens = self.search([('user_id', '=', token.user_id.id),
                                           ('id', '!=', token.id),
                                           ('ttype', '=', token.ttype)])
            for item in existing_tokens:
                item.unlink()
        except Exception as e:
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'create and unlink on email.activation',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s" % ("create", vals)})
            except Exception as e:
                pass
        return token

    def send_password_reset_email(self):
        try:
            template = self.env.ref('byte_api.password_reset_template')
            assert template._name == 'mail.template'
            template.send_mail(self.id, force_send=True, raise_exception=True)
            return {'status': True, 'intent': True, 'description': "Password Reset Token Sent to your email!"}
        except Exception as e:
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'send_password_reset_email',
                                          'model': str(self),
                                          'meta': ""})
            except Exception as e:
                # TODO THANOS LOG ERROR
                pass
            error = "Could not reset Password. An error Occurred. Try Again"
            return {"status": True, "intent": False, "description": error}

    def send_activation_email(self, called=True):
        try:
            template = self.env.ref('byte_api.activation_email_template')
            assert template._name == 'mail.template'
            template.with_context(lang=self.env.user.lang).send_mail(self.id, force_send=True, raise_exception=True)
            return
        except Exception as e:
            try:
                error_message_obj = self.env['byte.error.message']
                error_message_obj.create({'name': e,
                                          'exception': True,
                                          'method': 'send_activation_email',
                                          'model': str(self),
                                          'meta': "Parameter %s  Parameter value %s" % ("Called", called)})
            except Exception as e:
                pass
            if called:
                raise fields.UserError(e)
            else:
                return

    def auto_user_check_token(self):
        # lets check if the token is still valid
        for rec in self:
            if rec.user_id:
                if fields.Datetime.from_string(rec.expiry_date) < fields.Datetime.from_string(fields.Datetime.now()):
                    rec.reset_attempt += 1
                    return False
                elif fields.Datetime.from_string(rec.expiry_date) > fields.Datetime.from_string(fields.Datetime.now()):
                    return rec.token
                else:
                    return False

    def cron_delete_expired_tokens(self):
        existing_tokens = self.search([])
        for token in existing_tokens:
            if not token.auto_user_check_token():
                token.unlink()
