# -*- coding: utf-8 -*-
import functools
import hashlib
import logging
import os
from ast import literal_eval
import werkzeug

try:
    import simplejson as json
except ImportError:
    import json

import werkzeug.wrappers

import odoo
from odoo.http import request
from odoo import fields
_logger = logging.getLogger(__name__)


def api_response(data):
    return werkzeug.wrappers.Response(
        status=200,
        content_type='application/json; charset=utf-8',
        response=json.dumps(data),
    )


def get_fields_values_from_model(modelname, domain, fields_list, offset=0, limit=None, order=None, jdata=None):
    # Default filter
    cr, uid, context = request.cr, request.session.uid, request.context
    # cr._cnx.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
    records = request.env[modelname].sudo().search(domain, offset=offset, limit=limit, order=order)
    if not records:
        return {}
    fields_result = []
    for record in records:
        fields_result += [get_fields_values_from_one_record(record, fields_list)]

    return fields_result


def get_fields_values_from_one_record(record, fields_list):
    result = {}
    for field in fields_list:
        if type(field) == str:
            val = record[field]
            # If many2one _plane_ field
            try:
                val = val.id
            except:
                pass

            result[field] = val if (val or '0' in str(val)) else None
        elif type(field) == tuple and field[1] == 'BOOLEAN':
            result[field[0]] = record[field[0]] if record[field[0]] else False
        else:
            # Sample for One2many field: ('bank_ids', [('id', 'acc_number', 'bank_bic')])
            f_name, f_list = field[0], field[1]

            if type(f_list) == list:
                # Many (list of) records
                f_list = f_list[0]
                result[f_name] = []
                recs = record[f_name]
                for rec in recs:
                    result[f_name] += [get_fields_values_from_one_record(rec, f_list)]
            else:
                # One record
                rec = record[f_name]
                # protection against only one item without a comma
                if type(f_list) == str:
                    f_list = (f_list,)
                result[f_name] = get_fields_values_from_one_record(rec, f_list)

    return result


def convert_values_from_jdata_to_vals(modelname, jdata, creating=True):
    x2m_fields = [f for f in jdata if type(jdata[f]) == list]
    f_props = request.env[modelname].sudo().fields_get(x2m_fields)

    vals = {}
    for field in jdata:
        val = jdata[field]
        if type(val) != list:
            vals[field] = val
        else:
            # x2many
            #
            # Sample for One2many field:
            # 'bank_ids': [{'acc_number': '12345', 'bank_bic': '6789'}, {'acc_number': '54321', 'bank_bic': '9876'}]
            vals[field] = []
            field_type = f_props[field]['type']
            # if updating of 'many2many'
            if (not creating) and (field_type == 'many2many'):
                # unlink all previous 'ids'
                vals[field].append((5,))

            for jrec in val:
                rec = {}
                for f in jrec:
                    rec[f] = jrec[f]

                if field_type == 'one2many':
                    if creating:
                        vals[field].append((0, 0, rec))
                    else:
                        if 'id' in rec:
                            id = rec['id']
                            del rec['id']
                            if len(rec):
                                # update record
                                vals[field].append((1, id, rec))
                            else:
                                # remove record
                                vals[field].append((2, id))
                        else:
                            # create record
                            vals[field].append((0, 0, rec))

                elif field_type == 'many2many':
                    # link current existing 'id'
                    vals[field].append((4, rec['id']))
    return vals


def create_object(modelname, vals):
    # cr._cnx.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
    return request.env[modelname].sudo().create(vals)


def update_object(modelname, obj_id, vals):
    # cr._cnx.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
    # get object
    object_id = request.env[modelname].sudo().search([('id', '=', obj_id)])
    if object_id:
        return object_id.sudo().write(vals)


def delete_object(modelname, obj_id):
    # cr._cnx.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
    object_id = request.env[modelname].sudo().search([('id', '=', obj_id)])
    if object_id:
        return object_id.sudo().unlink()


def call_method_of_object(modelname, obj_id, method, jdata):
    # cr, uid, context = request.cr, request.session.uid, request.context
    # cr._cnx.set_isolation_level(ISOLATION_LEVEL_READ_COMMITTED)
    # TODO Check this again
    record = request.env[modelname].sudo().search([('id', '=', obj_id)])
    # Validate method of model
    Method_of_model = getattr(record, method, None)
    if callable(Method_of_model):
        # Execute method of object (with/without context)
        # (Not optimal code! But 'inspect.getargspec(Method_of_model)' - don't work properly here!)
        try:
            res = Method_of_model(**jdata)
        except Exception as e:
            res = Method_of_model(**jdata)
    else:
        res = '__error__method_not_exist'
    return res


def wrap__resource__read_all(modelname, default_domain, success_code, OUT_fields):
    # Try convert http data into json:
    try:
        jdata = json.loads(request.httprequest.stream.read())
    except:
        jdata = {}
    # Default filter
    domain = default_domain or []
    # Get additional parameters
    if 'filters' in jdata:
        domain += literal_eval(str(jdata['filters']))
    if 'offset' in jdata:
        offset = int(jdata['offset'])
    else:
        offset = 0
    if 'limit' in jdata:
        limit = int(jdata['limit'])
    else:
        limit = None
    if 'order' in jdata:
        order = jdata['order']
    else:
        order = None
    if 'hash' in jdata:
        hash = jdata['hash']
    else:
        hash = None
    # protection against only one item without a comma
    if type(OUT_fields) == str:
        OUT_fields = (OUT_fields,)
    # Reading object's data:
    Objects_Data = get_fields_values_from_model(
        modelname=modelname,
        domain=domain,
        offset=offset,
        limit=limit,
        order=order,
        fields_list=OUT_fields,
        jdata=jdata,
    )
    dict_data = {
        'count': len(Objects_Data),
        'result': Objects_Data,
    }

    return api_response({'status': True, 'intent': True, 'description': "", "data": Objects_Data})


def wrap__resource__read_one(modelname, id, success_code, OUT_fields):
    # Default search field
    search_field = 'id'
    search_field_type = 'integer'
    # Try convert http data into json:
    try:
        jdata = json.loads(request.httprequest.stream.read())
        # Is there a search field?
        if jdata.get('search_field'):
            search_field = jdata['search_field']
            # Get search field type:
            search_field_type = request.env[modelname].sudo().fields_get([search_field])[search_field]['type']
    except:
        pass
    # Сheck id
    obj_id = None
    if search_field_type == 'integer':
        try:
            obj_id = int(id)
        except:
            pass
    else:
        obj_id = id
    if not obj_id:
        return error_response_400__invalid_object_id()
    # protection against only one item without a comma
    if type(OUT_fields) == str:
        OUT_fields = (OUT_fields,)
    # Reading object's data:
    Object_Data = get_fields_values_from_model(
        modelname=modelname,
        domain=[(search_field, '=', obj_id)],
        fields_list=OUT_fields
    )
    if Object_Data:
        return api_response({'status': True, 'intent': True, 'description': "", "data": Object_Data[0]})
    else:
        return error_response_404__not_found_object_in_odoo()


def wrap__resource__read_code(modelname, code, success_code, OUT_fields):
    # Default search field
    search_field = 'code'
    search_field_type = 'integer'
    # Try convert http data into json:
    try:
        jdata = json.loads(request.httprequest.stream.read())
        # Is there a search field?
        if jdata.get('search_field'):
            search_field = jdata['search_field']
            # Get search field type:
            search_field_type = request.env[modelname].sudo().fields_get([search_field])[search_field]['type']
    except:
        pass
    # Сheck id
    obj_id = None
    if search_field_type == 'integer':
        try:
            obj_id = int(code)
        except:
            pass
    else:
        obj_id = code
    if not obj_id:
        return error_response_400__invalid_object_id()
    # protection against only one item without a comma
    if type(OUT_fields) == str:
        OUT_fields = (OUT_fields,)
    # Reading object's data:
    Object_Data = get_fields_values_from_model(
        modelname=modelname,
        domain=[(search_field, '=', obj_id)],
        fields_list=OUT_fields
    )
    if Object_Data:
        return api_response({'status': True, 'intent': True, 'description': "", "data": Object_Data[0]})
    else:
        return error_response_404__not_found_object_in_odoo()


def wrap__resource__create_one(modelname, default_vals, success_code, OUT_fields=('id',)):
    # Convert http data into json:
    jdata = json.loads(request.httprequest.stream.read())
    # Convert json data into Odoo vals:
    try:
        vals = convert_values_from_jdata_to_vals(modelname, jdata)
        # Set default fields:
        if default_vals:
            vals.update(default_vals)
        # Try create new object
        try:
            new_id = create_object(modelname, vals)
            odoo_error = ''
        except Exception as e:
            new_id = None
            odoo_error = e
        if type(new_id) == dict:
            if new_id.get('error'):
                error = new_id['error']
            else:
                error = 'Error Occurred'
            return error_response_409__not_created_object_in_odoo(error)
        if new_id and type(new_id.id) == int:
            # protection against only one item without a comma
            if type(OUT_fields) == str:
                OUT_fields = (OUT_fields,)
            response_json = get_fields_values_from_model(
                modelname=modelname,
                domain=[('id', '=', new_id.id)],
                fields_list=OUT_fields
            )[0]
            return api_response({'status': True, 'intent': True, 'description': "", "data": response_json})
        else:
            return error_response_409__not_created_object_in_odoo(odoo_error)
    except Exception as e:
        return api_response({"status": True, "intent": False, "description": "Create Error Occurred"})


def wrap__resource__update_one(modelname, id, success_code, OUT_fields=('id',)):
    # Сheck id
    obj_id = None
    try:
        obj_id = int(id)
    except:
        pass
    if not obj_id:
        return error_response_400__invalid_object_id()
    # Convert http data into json:
    jdata = json.loads(request.httprequest.stream.read())
    # Convert json data into Odoo vals:
    vals = convert_values_from_jdata_to_vals(modelname, jdata, creating=False)
    # Try update the object
    try:
        res = update_object(modelname, obj_id, vals)
        odoo_error = ''
    except Exception as e:
        res = None
        odoo_error = e.message
    if res:
        response_json = get_fields_values_from_model(
            modelname=modelname,
            domain=[('id', '=', obj_id)],
            fields_list=OUT_fields
        )[0]
        return api_response({'status': True, 'intent': True, 'description': "", "data": response_json})
    else:
        return error_response_409__not_updated_object_in_odoo(odoo_error)


def wrap__resource__delete_one(modelname, id, success_code):
    # Сheck id
    obj_id = None
    try:
        obj_id = int(id)
    except:
        pass
    if not obj_id:
        return error_response_400__invalid_object_id()
    # Try delete the object
    try:
        res = delete_object(modelname, obj_id)
        odoo_error = ''
    except Exception as e:
        res = None
        odoo_error = e.message
    if res:
        return api_response({'status': True, 'intent': True, 'description': "", "data": {}})
    else:
        return error_response_409__not_deleted_object_in_odoo(odoo_error)


def wrap__resource__call_method(modelname, id, method):
    # Сheck id
    obj_id = None
    try:
        obj_id = int(id)
    except:
        pass
    if not obj_id:
        return error_response_400__invalid_object_id()
    # Try convert http data into json:
    try:
        jdata = json.loads(request.httprequest.stream.read())
    except:
        jdata = {}
    # Try call method of object
    _logger.info("Try call method of object: modelname == %s; obj_id == %s; method == %s; len(jdata) == %s" \
                 % (modelname, obj_id, method, len(jdata)))
    _logger.debug("jdata == %s" % jdata)
    try:
        res = call_method_of_object(modelname, obj_id, method, jdata)
        odoo_error = ''
    except Exception as e:
        res = None
        odoo_error = e
        _logger.debug("Error while calling method!!!!!!!!!!!!!!!!!!! %s %s" % (odoo_error, e))
    if res:
        if res == '__error__method_not_exist':
            return error_response_501__method_not_exist_in_odoo()
        else:
            return api_response(res)
    else:

        if not res:
            _logger.debug("Second Error while calling method!!!!!!!!!!!!!!!!!!! %s" % odoo_error)
            return error_response_409__not_called_method_in_odoo(False)
        _logger.debug("Third Error while calling method!!!!!!!!!!!!!!!!!!! %s" % odoo_error)
        return error_response_409__not_called_method_in_odoo(odoo_error)


def check_authorization(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        client_id = request.httprequest.headers.get('clientId')
        if client_id != '12345':
            return api_response({"status": True, "intent": False, "description": 'UnAuthorized Access'})
        return func(self, *args, **kwargs)

    return wrapper


def check_permissions(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        _logger.info("Check permissions...")

        # Get access token from http header
        access_token = request.httprequest.headers.get('accessToken')
        client_id = request.httprequest.headers.get('clientId')
        if client_id != '12345':
            return api_response({"status": True, "intent": False, "description": 'UnAuthorized'})
        if not access_token:
            error_description = "No access token was provided in request header!"
            return api_response({"status": True, "intent": False, "description": error_description})

        # Validate access token
        access_token_data = token_store.fetch_by_access_token(access_token)
        if not access_token_data:
            return error_response_401__invalid_token()

        # Set session UID from current access token
        current_user = access_token_data['user_id']
        request.session.uid = current_user
        user = request.env['res.users'].sudo().search([('id', '=', current_user)])
        if user:
            # lets update the last seen of this user here
            try:
                user.env.cr.execute("UPDATE res_users SET last_seen='%s' where id=%s" % (fields.Datetime.now(), int(current_user)))
                request.session.uid = current_user
                request.env.uid = current_user
                request.env.user = user
            except Exception as e:
                user_obj.env.cr.rollback()

        # The code, following the decorator
        return func(self, *args, **kwargs)

    return wrapper


def api_response(dict_data):
    return werkzeug.wrappers.Response(
        status=200,
        content_type='application/json; charset=utf-8',
        # headers = None,
        response=json.dumps(dict_data),
    )


def error_response_400__invalid_object_id():
    error_description = "Invalid object 'id'!"
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_401__invalid_token():
    error_description = "Token is expired or invalid!"
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_404__not_found_object_in_odoo():
    error_description = "Not found object(s) in Demsup!"
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_409__not_created_object_in_odoo(odoo_error):
    error_description = odoo_error
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_409__not_updated_object_in_odoo(odoo_error):
    error_description = odoo_error
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_409__not_deleted_object_in_odoo(odoo_error):
    error_description = odoo_error
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_409__not_called_method_in_odoo(odoo_error):
    error_description = odoo_error
    return api_response({"status": True, "intent": False, "description": error_description})


def error_response_501__method_not_exist_in_odoo():
    error_description = "Method not exist in DemSup!"
    return api_response({"status": True, "intent": False, "description": error_description})


def generate_token(length=40):
    random_data = os.urandom(100)
    hash_gen = hashlib.new('sha512')
    hash_gen.update(random_data)
    return hash_gen.hexdigest()[:length]


# Read OAuth2 constants and setup Redis token store:
config = odoo.tools.config

access_token_expires_in = config.get('oauth2_access_token_expires_in', 1296000)
refresh_token_expires_in = config.get('oauth2_refresh_token_expires_in', 3888000)
redis_host = config.get('redis_host', 'localhost')
redis_port = config.get('redis_port', 6379)
redis_db = config.get('redis_db', 0)
redis_password = config.get('redis_password')
if redis_password in ('None', 'False'):
    redis_password = None
# Setup Redis token store and resources:

if redis_host and redis_port:
    from ..controllers import redisdb

    token_store = redisdb.RedisTokenStore(
        host=redis_host,
        port=redis_port,
        db=redis_db,
        password=redis_password)

    _logger.info("INFO: rest api successfully loaded!")
else:
    _logger.warning("WARNING: It's necessary to RESTART Odoo server after the installation of 'rest_api' module!")
