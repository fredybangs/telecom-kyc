from odoo import models, fields, api


class ResPartner(models.Model):
    _inherit = 'res.partner'

    kyc_application_ids = fields.One2many(
        'qcell_kyc.application',
        'partner_id',
        string='KYC Applications'
    )
    kyc_verified = fields.Boolean(
        string='KYC Verified',
        default=False,
        tracking=True
    )

    kyc_application_count = fields.Integer(
        string='KYC Applications',
        compute='_compute_kyc_application_count'
    )
    partner_gid = fields.Integer(string="Partner GID")
    additional_info = fields.Text(string="Additional Information")


    @api.depends('kyc_application_ids')
    def _compute_kyc_application_count(self):
        for partner in self:
            partner.kyc_application_count = len(partner.kyc_application_ids)
