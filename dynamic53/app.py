#!/usr/bin/env python
import sys
import re
import functools
import base64
import logging
import tornado.ioloop
import tornado.web
import tornado.options
from tornado.options import options
import tornado.httpserver
import boto
from boto.route53.exception import DNSServerError
from boto.route53.record import ResourceRecordSets

class NotInHostedZonesError(Exception): pass

def basic_authenticated(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        auth_hdr = self.request.headers.get("Authorization")
        if not auth_hdr:
            self.set_status(401)
            self.set_header("WWW-Authenticate", "Basic realm=dynamic53")
            self.finish()
            return
        else:
            b64up = auth_hdr[6:]
            try:
                auth_user, auth_password = base64.b64decode(b64up).split(':')
            except (TypeError, IndexError, ValueError):
                raise HTTPError(403)

            self.http_auth_user = auth_user
            self.http_auth_password = auth_password
            return method(self, *args, **kwargs)
    return wrapper
    #return tornado.web.asynchronous(wrapper)

def r53_change_record(name, values,
                      aws_access_key_id, aws_secret_access_key,
                      proxy=None, proxy_port=None,
                      type="A", ttl="600", comment=""):

    conn = boto.connect_route53(aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                proxy=proxy,
                                proxy_port=proxy_port
                                )
    res = conn.get_all_hosted_zones()

    hosted_zone_id = None
    for zoneinfo in res['ListHostedZonesResponse']['HostedZones']:
        zonename = zoneinfo['Name']
        _zone_id = zoneinfo['Id']
        _zone_id = re.sub('/hostedzone/', '', _zone_id)
        if zonename[-1] == '.':
            zonename = zonename[:-1]

        if name == zonename:
            hosted_zone_id = _zone_id
            break

        if name[-len(zonename):] == zonename:
            hosted_zone_id = _zone_id
            break
    if not hosted_zone_id:
        raise NotInHostedZonesError(name)

    changes = ResourceRecordSets(conn, hosted_zone_id, comment)
    
    response = conn.get_all_rrsets(hosted_zone_id, type, name, maxitems=1)
    if response:
        rrset = response[0]
        change1 = changes.add_change("DELETE", name, type, rrset.ttl)
        for old_value in rrset.resource_records:
            change1.add_value(old_value)
    change2 = changes.add_change("CREATE", name, type, ttl)
    for new_value in values.split(','):
        change2.add_value(new_value)
    return changes.commit()

class UpdateReqHandler(tornado.web.RequestHandler):
    @basic_authenticated
    def get(self):
        hostname = self.get_argument('hostname')
        myip = self.get_argument('myip', default=None)

        if not myip:
            #TODO: guess my ip
            pass
        try:
            res = r53_change_record(hostname, myip,
                                    self.http_auth_user, self.http_auth_password)
            logging.info(res)
        except NotInHostedZonesError:
            self.write('nohost')
        except DNSServerError:
            self.write('badauth')
        except:
            self.write('911')
        
        self.write('good')

settings = {
    "debug": True,
    }

application = tornado.web.Application([
    (r"/nic/update", UpdateReqHandler),
    ], **settings)

def main():
    tornado.options.define("bind_ip", default="127.0.0.1", type=str)
    tornado.options.define("port", default=8888, type=int)
    tornado.options.parse_command_line()
    
    bind_ip = options["bind_ip"].value()
    listen_port = options["port"].value()

    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(listen_port, address=bind_ip)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
