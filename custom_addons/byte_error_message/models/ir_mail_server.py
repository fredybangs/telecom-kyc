from odoo import models, fields


class IrMailServer(models.Model):
    _inherit = "ir.mail_server"

    def _get_test_email_addresses(self):
        self.ensure_one()
        email_from = self.smtp_user
        if not email_from:
            raise fields.UserError('Please configure an email on the current email server to simulate '
                              'sending an email message via this outgoing server')
        return email_from, email_from
