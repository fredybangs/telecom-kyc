from odoo import models, fields, api
from odoo.exceptions import UserError

class ByteErrorMessage(models.Model):
    _name = 'byte.error.message'
    _description = 'Error Message'

    create_date = fields.Datetime(string='Created On', readonly=True, default=fields.Datetime.now)
    exception = fields.Text(string='Exception', readonly=True)
    name = fields.Char(string='Name', readonly=True)
    model = fields.Char(string='Model', readonly=True)
    method = fields.Char(string='Method', readonly=True)
    meta = fields.Text(string='Meta', readonly=True)
    state = fields.Selection([
        ('pending', 'Pending'),
        ('resolved', 'Resolved'),
    ], string='Status', default='pending')

    def action_set_resolved(self):
        for record in self:
            if record.state != 'pending':
                raise UserError("Only records with status 'Pending' can be marked as resolved.")
            record.state = 'resolved'
