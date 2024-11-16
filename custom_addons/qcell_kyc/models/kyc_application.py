import logging
import re

import requests

from odoo import models, fields, api
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


def upload_image_to_imagebb(image_base64_string):
    api_key = 'b03bfa94ee382d828ab3da67e813a97a'
    endpoint = 'https://api.imgbb.com/1/upload'

    payload = {
        'key': api_key,
        'image': image_base64_string
    }

    response = requests.post(endpoint, data=payload)
    if response.status_code == 200:
        response_json = response.json()
        return response_json['data']['url']
    else:
        raise ValidationError("Image upload failed. Please check your ImgBB API key and try again.")


class KYCApplication(models.Model):
    _name = 'qcell_kyc.application'
    _description = 'KYC Application'
    _inherit = ['mail.thread', 'mail.activity.mixin']

    name = fields.Char(
        string='Application Reference',
        required=True,
        copy=False,
        readonly=True,
        default='New',
        tracking=True
    )
    partner_id = fields.Many2one(
        'res.partner',
        string='Customer',
        required=True,
        tracking=True
    )
    id_type = fields.Selection([
        ('passport', 'Passport'),
        ('driver_license', 'Driver License'),
        ('voter_id', 'Voter ID'),
        ('national_id', 'National ID'),
    ], string='ID Type', required=True, tracking=True)
    id_number = fields.Char(string='ID Number', required=True, tracking=True)
    phone_number = fields.Char(string='Phone Number', required=True, tracking=True)
    current_address = fields.Char(string='Current Address')
    permanent_address = fields.Char(string='Permanent Address')
    id_document = fields.Image(string='ID Document')
    id_document_url = fields.Char(string="ID Image Url", readonly=True)
    proof_of_address = fields.Image(string='Proof of Address')
    proof_of_address_url = fields.Char(string="Proof of Address URL", readonly=True)
    selfie = fields.Image(string='Selfie')
    selfie_url = fields.Char(string="User Photo URL", readonly=True)
    id_expiry_date = fields.Date(string='ID Expiry Date')
    document_upload_date = fields.Datetime(string='Document Upload Date', default=fields.Datetime.now)
    state = fields.Selection([
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ], string='Status', readonly=True, default='draft', tracking=True)
    verification_notes = fields.Text(string='Verification Notes')

    _sql_constraints = [
        ('name_unique', "CHECK(name = 'New' OR name IS NOT NULL)", 'The Application Reference must be unique.'),
        ('phone_number_unique', 'unique(phone_number)', 'The phone number must be unique.'),
    ]

    @api.model
    def create(self, vals):
        # Generate unique reference if 'name' is 'New'
        if vals.get('name', 'New') == 'New':
            vals['name'] = self.env['ir.sequence'].next_by_code('qcell_kyc.application') or 'New'
        vals['document_upload_date'] = fields.Datetime.now()

        # Upload images to ImgBB and store URLs
        if 'id_document' in vals and vals['id_document']:
            id_document_base64 = vals['id_document']
            vals['id_document_url'] = upload_image_to_imagebb(id_document_base64)

        if 'proof_of_address' in vals and vals['proof_of_address']:
            proof_of_address_base64 = vals['proof_of_address']
            vals['proof_of_address_url'] = upload_image_to_imagebb(proof_of_address_base64)

        if 'selfie' in vals and vals['selfie']:
            selfie_base64 = vals['selfie']
            vals['selfie_url'] = upload_image_to_imagebb(selfie_base64)

        return super(KYCApplication, self).create(vals)

    @api.constrains('id_expiry_date')
    def _check_id_expiry_date(self):
        for record in self:
            if record.id_expiry_date and record.id_expiry_date < fields.Date.today():
                raise UserError("The ID document has expired.")

    @api.constrains('id_number')
    def _check_id_number_format(self):
        for record in self:
            if not re.match(r'^[A-Z0-9]+$', record.id_number):
                raise UserError("ID Number must contain only letters and numbers.")

    @api.constrains('phone_number')
    def _check_phone_number_format_and_uniqueness(self):
        for record in self:
            # Define the regex pattern
            pattern = r'^232(31|32|34)\d{6}$'
            if not re.match(pattern, record.phone_number):
                raise ValidationError(
                    "Phone Number must start with '232' followed by '31', '32', or '34', and then 6 digits.\n"
                    "Valid examples:\n"
                    "- 23232123456\n"
                    "- 23231123456\n"
                    "- 23234123456"
                )
            # Uniqueness is already enforced by SQL constraint, but double-check if needed
            existing = self.search([
                ('phone_number', '=', record.phone_number),
                ('id', '!=', record.id)
            ], limit=1)
            if existing:
                raise ValidationError("The phone number must be unique. This number is already in use.")

    def action_generate_sequence(self):
        """Generate and assign a sequence to the 'name' field if it is 'New'."""
        for record in self:
            if record.name != 'New':
                raise UserError("Sequence has already been generated.")
            _logger.info("Generating sequence for KYC Application ID %s", record.id)
            application_reference = self.env['ir.sequence'].sudo().next_by_code('qcell_kyc.application')
            _logger.info("Generated sequence: %s", application_reference)
            if not application_reference:
                _logger.error(
                    "Failed to generate application reference: Sequence 'qcell_kyc.application' returned None.")
                raise UserError("Failed to generate application reference.")
            record.name = application_reference
            _logger.info("Assigned application reference %s to KYC Application ID %s", application_reference, record.id)

    def action_submit(self):
        for record in self:
            if record.state != 'draft':
                raise UserError("Only draft applications can be submitted.")

            if record.name == 'New':
                max_retries = 5  # Limit retries to avoid an infinite loop
                unique_reference_generated = False

                _logger.info("Attempting to generate unique sequence for KYC Application ID %s", record.id)

                for _ in range(max_retries):
                    # Generate a new sequence
                    application_reference = self.env['ir.sequence'].sudo().next_by_code('qcell_kyc.application')
                    if not application_reference:
                        _logger.error(
                            "Failed to generate application reference: Sequence 'qcell_kyc.application' returned None.")
                        raise UserError("Failed to generate application reference.")

                    # Check if the reference already exists
                    existing_reference = self.env['qcell_kyc.application'].sudo().search(
                        [('name', '=', application_reference)], limit=1)

                    if not existing_reference:
                        # No duplicate found; assign this reference
                        record.name = application_reference
                        unique_reference_generated = True
                        _logger.info("Assigned unique application reference %s to KYC Application ID %s",
                                     application_reference, record.id)
                        break
                    else:
                        _logger.warning("Generated duplicate application reference %s, retrying...",
                                        application_reference)

                if not unique_reference_generated:
                    # Fetch the latest application reference in case retries failed
                    last_record = self.env['qcell_kyc.application'].sudo().search([], order='name desc', limit=1)
                    if last_record:
                        # Extract numerical part assuming the sequence format is predictable, e.g., "KYC00001"
                        last_number = re.search(r'\d+$', last_record.name)
                        if last_number:
                            next_sequence = int(last_number.group()) + 1
                            record.name = f"KYC{str(next_sequence).zfill(5)}"  # Assuming a padding of 5 digits
                            unique_reference_generated = True
                            _logger.info("Assigned fallback application reference %s to KYC Application ID %s",
                                         record.name, record.id)

                if not unique_reference_generated:
                    _logger.error("Could not generate a unique application reference after %s retries.", max_retries)
                    raise ValidationError("Could not generate a unique application reference. Please try again later.")

            # Update the state to submitted after successfully assigning a unique reference
            record.state = 'submitted'

    def action_verify(self):
        for record in self:
            if record.state != 'submitted':
                raise UserError("Only submitted applications can be verified.")
            record.state = 'verified'
            record.partner_id.kyc_verified = True

    def action_reject(self):
        self.state = 'rejected'

    def action_reset(self):
        self.state = 'draft'
        self.verification_notes = False
