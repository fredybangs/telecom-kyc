# telecom_kyc/__manifest__.py
{
    'name': 'Qcell KYC',
    'version': '1.0',
    'category': 'Telecom',
    'summary': 'KYC system for Qcell Sierra Leone',
    'description': """
        A comprehensive KYC system for Qcell to verify customer identities and comply with international standards.
    """,
    'author': 'Alfred Bangura',
    'website': 'https://thespaceman.tech',
    'depends': ['byte_error_message', 'base','contacts','mail'],
    'data': [
        'data/data.xml',
        'security/security.xml',
        'security/ir.model.access.csv',
        'views/email_activation.xml',
        'views/kyc_application_views.xml',
        # 'views/res_partners_views.xml',
        'views/kyc_menu.xml'
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
}
