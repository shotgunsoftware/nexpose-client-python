# Future Imports for py2/3 backwards compat.
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from builtins import object
from .xml_utils import get_attribute
from future import standard_library
standard_library.install_aliases()

from .nexpose_tag import Tag


class AssetHostTypes(object):
    Empty = ''
    Guest = 'GUEST'
    Hypervisor = 'HYPERVISOR'
    Physical = 'PHYSICAL'
    Mobile = 'MOBILE'


class AssetBase(object):
    def InitializeFromXML(self, xml_data):
        self.id = int(get_attribute(xml_data, 'id', self.id))
        self.risk_score = float(get_attribute(xml_data, 'riskscore', self.risk_score))

    def InitializeFromJSON(self, json_dict):
        self.id = json_dict['id']
        try:
            self.risk_score = json_dict['assessment']['json']['risk_score']
        except KeyError:
            pass

    def __init__(self):
        self.id = 0
        self.risk_score = 0.0


class AssetSummary(AssetBase):
    @staticmethod
    def Create():
        return AssetSummary()

    @staticmethod
    def CreateFromXML(xml_data, site_id=None):
        asset = AssetSummary.Create()
        asset.InitializeFromXML(xml_data)
        asset.site_id = int(site_id if site_id is not None else get_attribute(xml_data, 'site-id', asset.site_id))
        asset.host = get_attribute(xml_data, 'address', asset.host)
        asset.risk_factor = float('0' + get_attribute(xml_data, 'riskfactor', asset.risk_factor))  # riskfactor can be an emtpy string
        return asset

    def __init__(self):
        AssetBase.__init__(self)
        self.site_id = 0
        self.host = ''
        self.risk_factor = 1.0


class AssetDetails(AssetBase):
    @staticmethod
    def CreateFromJSON(json_dict):
        host_names = json_dict["host_names"]
        host_type = json_dict["host_type"]
        details = AssetDetails()
        details.InitializeFromJSON(json_dict)
        details.ip_address = json_dict["ip"]
        details.mac_address = json_dict["mac"]
        details.addresses = json_dict["addresses"]
        if host_names is not None:
            details.host_names = host_names
        if host_type is not None:
            details.host_type = host_type
        details.os_name = json_dict["os_name"]
        details.os_cpe = json_dict["os_cpe"]
        try:
            assessment = json_dict['assessment']['json']
        except KeyError:
            pass
        else:
            details.last_scan_id = assessment['last_scan_id']
            details.last_scan_date = assessment['last_scan_date']

        try:
            tags = json_dict['tags']['json']['resources']
        except KeyError:
            pass
        else:
            for tag in tags:
                details.tags.append(Tag.CreateFromJSON(tag))

        details.unique_identifiers = []
        try:
            unique_identifiers_data = json_dict['unique_identifiers']['json']
        except KeyError:
            # Unique Identifiers not fetched
            pass
        else:
            for identifier in unique_identifiers_data:
                details.unique_identifiers.append(
                    UniqueIdentifier.CreateFromJSON(identifier)
                )

        details.vulnerability_instances = []
        try:
            vulnerabilities_instance_list = json_dict['vulnerability_instances']['json']
        except KeyError:
            # Vulnerability_instances are not present
            pass
        else:
            for vuln in vulnerabilities_instance_list:
                details.vulnerability_instances.append(
                    VulnerabilityInstanceEntity.CreateFromJSON(vuln))

        details.vulnerabilities = []
        try:
            vulnerabilities_list = json_dict['vulnerabilities']['json']
        except KeyError:
            # Vulnerabilities are not present
            pass
        else:
            for vuln in vulnerabilities_list:
                details.vulnerabilities.append(
                    VulnerabilityEntity.CreateFromJSON(vuln)
                )
        details.software = []
        try:
            software_list = json_dict['software']['json']
        except KeyError:
            # No software list
            pass
        else:
            for software in software_list:
                details.software.append(
                     SoftwareEntity.CreateFromJSON(software))
        details.services = []
        try:
            services_list = json_dict['services']['json']
        except KeyError:
            # Services are not present
            pass
        else:
            for service in services_list:
                details.services.append(
                     ServiceEntity.CreateFromJSON(service))
        # TODO:
        # ----begin
        details.files = []
        details.group_accounts = []
        details.user_accounts = []
        # TODO:
        # ----end
        return details

    def __init__(self):
        AssetBase.__init__(self)
        self.ip_address = ''
        self.mac_address = ''
        self.addresses = []
        self.host_names = []
        self.host_type = AssetHostTypes.Empty
        self.os_name = ''
        self.os_cpe = ''
        self.last_scan_id = 0
        self.last_scan_date = ''
        self.files = []
        self.vulnerability_instances = []
        self.unique_identifiers = []
        self.group_accounts = []
        self.user_accounts = []
        self.vulnerabilities = []
        self.software = []
        self.services = []
        self.tags = []


class UniqueIdentifier(object):

    def __init__(self):
        self.source = ''
        self.id = ''

    @staticmethod
    def CreateFromJSON(json_dict):
        unique_identifier = UniqueIdentifier()
        unique_identifier.source = json_dict['source']
        unique_identifier.id = json_dict['id']
        return unique_identifier

    def __repr__(self):
        return '<UniqueIdentifier {type}: {id}>'.format(
            type=self.source,
            id=self.id,
        )

class VulnerabilityEntity(object):

    def __init__(self):
        self.url = ''
        self.id = ''
        self.vulnerability_definition = ''
        self.title = ''

    @staticmethod
    def CreateFromJSON(json_dict):
        vulnerability_entity = VulnerabilityEntity()
        vulnerability_entity.url = json_dict['url']
        vulnerability_entity.id = json_dict['id']
        vulnerability_entity.vulnerability_definition = json_dict['vulnerability_definition']
        vulnerability_entity.title = json_dict['title']
        return vulnerability_entity

    def __repr__(self):
        return '<VulnerabilityEntity {title}: {id}>'.format(
            title=self.title,
            id=self.id,
        )


class ServiceEntity(object):

    def __init__(self):
        self.url = ''
        self.protocol = ''
        self.port = ''
        self.name = ''
        self.vulnerabilities = []

    @staticmethod
    def CreateFromJSON(json_dict):
        service_entity = ServiceEntity()
        service_entity.url = json_dict['url']
        service_entity.protocol = json_dict['protocol']
        service_entity.port = json_dict['port']
        service_entity.name = json_dict['name']
        vuln_list = json_dict['vulnerabilities']
        for vuln in vuln_list:
            print(" -- vuln --:", vuln)
            service_entity.vulnerabilities.append(
                  VulnerabilityEntity.CreateFromJSON(vuln))
        return service_entity

    def __repr__(self):
        return '<ServiceEntity {title}: {id}>'.format(
            title=self.name,
            id=self.protocol,
        )

class SoftwareEntity(object):

    def __init__(self):
        self.product = ''
        self.vendor = ''
        self.family = ''
        self.url = ''
        self.version = ''
        self.type = ''

    @staticmethod
    def CreateFromJSON(json_dict):
        software_entity = SoftwareEntity()
        software_entity.product = json_dict['product']
        software_entity.vendor = json_dict['vendor']
        software_entity.family = json_dict['family']
        software_entity.url = json_dict['url']
        software_entity.version = json_dict['version']
        software_entity.type = json_dict['type']
        return software_entity

    def __repr__(self):
        return '<SoftwareEntity {title}: {id}>'.format(
            title=self.product,
            id=self.version,
        )

class VulnerabilityInstanceEntity(object):

    def __init__(self):
        self.status = ''
        self.asset_id = ''
        self.scan_id = ''
        self.protocol = ''
        self.asset_ip_address = ''
        self.service = ''
        self.url = ''
        self.key = ''
        self.date = ''
        self.port = ''
        self.vulnerability_id = ''
        self.proof = ''

    @staticmethod
    def CreateFromJSON(json_dict):
        vulnerability_instance_entity = VulnerabilityInstanceEntity()
        vulnerability_instance_entity.status = json_dict['status']
        vulnerability_instance_entity.asset_id = json_dict['asset_id']
        vulnerability_instance_entity.scan_id = json_dict['scan_id']
        vulnerability_instance_entity.protocol = json_dict['protocol']
        vulnerability_instance_entity.asset_ip_address = json_dict['asset_ip_address']
        vulnerability_instance_entity.service = json_dict['service']
        vulnerability_instance_entity.url = json_dict['url']
        vulnerability_instance_entity.key = json_dict['key']
        vulnerability_instance_entity.date = json_dict['date']
        vulnerability_instance_entity.port = json_dict['port']
        vulnerability_instance_entity.vulnerability_id = json_dict['vulnerability_id']
        vulnerability_instance_entity.proof = json_dict['proof']
        return vulnerability_instance_entity

    def __repr__(self):
        return '<VulnerabilityInstanceEntity {title}: {id}>'.format(
            title=self.service,
            id=self.proof,
        )

