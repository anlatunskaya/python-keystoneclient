# Copyright 2011 OpenStack Foundation
# Copyright 2011 Nebula, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import urllib

from keystoneclient import base


class Attestation(base.Resource):
    """Represents a Keystone user"""
    def __repr__(self):
        return "<Instance %s>" % self._info

    def delete(self):
        return self.manager.delete(self)


class AttestationManager(base.ManagerWithFind):
    """Manager class for manipulating Keystone users."""
    resource_class = Attestation

    def get(self, id):
        return self._get("/attestation/%s" % base.getid(user), "key_data")

    def update(self, user, **kwargs):
        """Update user data.

        Supported arguments include ``name``, ``email``, and ``enabled``.
        """
        # FIXME(gabriel): "tenantId" seems to be accepted by the API but
        #                 fails to actually update the default tenant.
        params = {"user": kwargs}
        params['user']['id'] = base.getid(user)
        url = "/users/%s" % base.getid(user)
        return self._update(url, params, "user")

    def update_enabled(self, user, enabled):
        """Update enabled-ness."""
        params = {"user": {"id": base.getid(user),
                           "enabled": enabled}}

        self._update("/users/%s/OS-KSADM/enabled" % base.getid(user), params,
                     "user")

    def update_password(self, user, password):
        """Update password."""
        params = {"user": {"id": base.getid(user),
                           "password": password}}

        return self._update("/users/%s/OS-KSADM/password" % base.getid(user),
                            params, "user")

    def update_own_password(self, origpasswd, passwd):
        """Update password."""
        params = {"user": {"password": passwd,
                           "original_password": origpasswd}}

        return self._update("/OS-KSCRUD/users/%s" % self.api.user_id, params,
                            response_key="access",
                            method="PATCH",
                            management=False)

    def update_tenant(self, user, tenant):
        """Update default tenant."""
        params = {"user": {"id": base.getid(user),
                           "tenantId": base.getid(tenant)}}

        # FIXME(ja): seems like a bad url - default tenant is an attribute
        #            not a subresource!???
        return self._update("/users/%s/OS-KSADM/tenant" % base.getid(user),
                            params, "user")

    def create(self, hostname, pcrs, auth_type, uuid, pkey, pure_hash, service):
        """Create a host key entity."""
        params = {"key_data": {"hostname": hostname,
                           "PCRs": pcrs,
                           "auth_type": auth_type,
                           "uuid": uuid,
                           "pkey": pkey,
                           "pure_hash": pure_hash,
                           "service": service}}
        return self._create('/attestation', params, "key_id", return_raw=True)

    def find(self, hostname, service):
        """Create a host key entity."""
        params = {"key_data": {"hostname": hostname,
                           "service": service}}
        return self._post('/attestation/find', params, "key_data", return_raw=True)

    def validate(self, id, salted_hash, salt):
        """Create a host key entity."""
        params = {"key_data": {"id": id,
                           "salted_hash": salted_hash,
                           "salt": salt}}
        url='/attestation/validate'
        return self._post(url, params, "key_data", return_raw=True)


    def delete(self, user):
        """Delete a user."""
        return self._delete("/users/%s" % base.getid(user))

    def list(self, tenant_id=None, limit=None, marker=None):
        """Get a list of users (optionally limited to a tenant).

        :rtype: list of :class:`User`
        """

        params = {}
        if limit:
            params['limit'] = int(limit)
        if marker:
            params['marker'] = marker

        query = ""
        if params:
            query = "?" + urllib.urlencode(params)

        if not tenant_id:
            return self._list("/users%s" % query, "users")
        else:
            return self._list("/tenants/%s/users%s" % (tenant_id, query),
                              "users")

    def list_roles(self, user, tenant=None):
        return self.api.roles.roles_for_user(base.getid(user),
                                             base.getid(tenant))
