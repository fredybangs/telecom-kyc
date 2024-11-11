from odoo import models, fields


class ResCompany(models.Model):
    _inherit = 'res.company'

    token_time_out = fields.Integer(string="Token Timeout (In Minutes)", default=10)
    email_from = fields.Char(string='Email From')
    fcm_token = fields.Char(string='Push Token Key')
