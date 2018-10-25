#!/usr/bin/env python2

import os, sys
import subprocess
from time import sleep
from xml.etree.ElementTree import XML
import boto3
from pprint import pprint, pformat

# This script was designed to instantiate and tear down a VPN connection to an AWS VPC on-demand, so as not to be charged when unused.

# Notes:
# -This script can block indefinitely while waiting for resources to be created.
# -Terminology in libreswan is confusing, and that concept has been adopted here. In this script, IPSec refers to the local side of the VPN connection and VPC VPN refers to the AWS side. TODO: link this to ipsec's left and right

# Limitations:
# -At present, partial VPN connection hours are billed as a full hour. Therefore, this script should be run no more often than once an hour.
# -This script only supports one subnet on each end of the IPSec tunnel. When attempting to specify multiple subnets, IPSec (Pluto) instatiates a tunnel for each pair of subnets. This seems to work fine from the tunnel perspective, but the Linux host was sending ICMP Redirects while also forwarding the traffic.
# -This script does not attempt to handle firewall rules. Because of complex interface configurations, firewall rules will be implementation specific. Here is a generic example using FirewallD (IPTables passthrough).
#  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 10 -d 10.0.0.0/8 -s 192.168.1.0/24 -j ACCEPT
# -Because we can't ensure that we determine the same %defaultroute information as IPSec (Pluto) did, the outgoing IP of the local system needs to be specified.
# -New connections are not verified. This script simply write the configuration and asks IPSec (Pluto) to connect.
# -It isn't currenlty possible to implement runtime only IPSec (Pluto) configurations. The connections can be configured in the runtime, but the secrets still need to be written to the disk.

# Exit codes:
# 1) Incorrect syntax.
# 2) Multiple VPN connections are defined.
# 3) Connection mismatch.
# 4) No available VPN endpoints.
# 5) VGW error.
# 6) CGW error.
# 7) Bad VPN connection state.
# 8) Connection error.

# TODO:
# -Swap left and right so that left is local.

# Enhancements:
# -Support more than one key.
# -Automatic resolution of multiple connections on either end.
# -Detect outside IP address changes and re-create CGW.
# -Handle exceptions.
# -May be able to use internal IP for CGW rather than public, allowing multiple VPNs from behind the same firewall and obviating the problem of the public IP changing.
# -Remove assumptions about file locations.

# Cleanup:
# -Enhance readability.
# -Documentation
# -Switch to the print() function rather than print statement.
# -Class variables and functions should not reference global variables or functions.
# -Class variables should not be referenced directly from outside of the class.
# -Replace prints and exits in classes with exceptions and returns.
# -Move dependencies into the classes.


# Your configurations here.
local_ip = '192.168.1.10'
ipsec_subnet = '192.168.1.0/24'
vpc_vpn_subnet = '10.0.0.0/8'
vgw_id = 'vgw-abcdef01'
tag_key = 'Name'
tag_value = 'avvem00'
use_files = True  # Should the IPSec configurations be written persistently? Currently, 'True' is the only valid value.
autostart = False  # Only relevant if use_files == True. Start connection with the ipsec daemon?
region = 'us-east-1'

# Derived, but overridable variables.
ipsec_conn_prefix = sys.argv[0].rsplit('/', 1)[-1] + '_' + tag_value

# Support variables.
encLookup = {'aes-128-cbc': 'aes128'}
authLookup = {'hmac-sha1-96': 'sha1', 'sha1': 'sha1'}
pfsLookup = {'group2': 'yes'}


class VpcCgw:
	metadata = ''

	def __init__(self, client_output=None):
		if client_output:
			self.parse(client_output)

	def create(self, client, ip, tags, bgp_asn=65000):
		client_output = client.create_customer_gateway(BgpAsn=bgp_asn, PublicIp=ip, Type='ipsec.1')
		if client_output['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		self.parse(client_output['CustomerGateway'])

		client.create_tags(Resources=[self.metadata['CustomerGatewayId']], Tags=tags)

		print 'Waiting for CGW to be created.',
		sys.stdout.flush()
		self.waitPending(client, progress=True)

	def destroy(self, client):
		vpn_conns = client.describe_vpn_connections(Filters=[{'Name': 'customer-gateway-id', 'Values': [self.metadata['CustomerGatewayId']]}])
		if vpn_conns['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		vpn_conns = map(lambda b: VpcVpnConnection(b), vpn_conns['VpnConnections'])
		vpn_conns = [c for c in vpn_conns if c.metadata['State'] != 'deleted']

		# Check associated VPN connection tags. Ignore and quit if not a managed VPN connection.
		for v in vpn_conns:
			if not v.containsTag({'Name': 'tag:' + tag_key, 'Values': [tag_value]}):
				print 'Unmanaged VPN connection associated to CGW. Not deleteing CGW.'
				return

		# Check associated VPN connection tunnel states.
		# Should we delete them?
		for v in vpn_conns:
			# TODO: switch this over to try/catch
			if v.hasUp():
				print 'Associated VPN connection is in use. Not deleteing CGW.'
				return
			else:
				v.destroy(client)

		# Delete CGW.
		client.delete_customer_gateway(CustomerGatewayId=self.metadata['CustomerGatewayId'])

	def parse(self, client_output):
		self.metadata = client_output

	# This function will block until the state changes.
	def waitPending(self, client, progress=False):
		while self.metadata['State'] == 'pending':
			sleep(5)
			if progress: print '.',
			sys.stdout.flush()
			self.update(client)
		if progress: print

	def update(self, client):
		client_output = client.describe_customer_gateways(CustomerGatewayIds=[self.metadata['CustomerGatewayId']])
		if client_output['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		self.parse(client_output['CustomerGateways'][0])

class VpcVpnConnection:
	metadata = ''

	def __init__(self, client_output=None):
		if client_output:
			self.parse(client_output)

	def __str__(self):
		pass

	def containsTag(self, tag):
		return tag in self.metadata['Tags']

	def create(self, client, vgw_id, cgw, static_route, routes, tags):
		client_output = client.create_vpn_connection(CustomerGatewayId=cgw.metadata['CustomerGatewayId'], VpnGatewayId=vgw_id, Type='ipsec.1', Options={'StaticRoutesOnly': static_route})
		if client_output['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		self.parse(client_output['VpnConnection'])

		client.create_tags(Resources=[self.metadata['VpnConnectionId']], Tags=tags)
		for route in routes:
			client.create_vpn_connection_route(VpnConnectionId=self.metadata['VpnConnectionId'], DestinationCidrBlock=route['DestinationCidrBlock'])
			client.create_vpn_connection_route(VpnConnectionId=self.metadata['VpnConnectionId'], DestinationCidrBlock=route['DestinationCidrBlock'])

		print 'Waiting for VPN connection to be created.',
		sys.stdout.flush()
		self.waitPending(client, progress=True)

	def destroy(self, client):
		self.update(client)
		
		if self.hasUp():
			print 'VPN connection is in use. Not deleteing.'
			return

		client.delete_vpn_connection(VpnConnectionId=self.metadata['VpnConnectionId'])

	def parse(self, client_output):
		self.metadata = client_output
		# Convert the CustomerGatewayConfiguration to an xml object.
		# It might be better to base this on the state of the VPN connection.
		if 'CustomerGatewayConfiguration' in self.metadata:
			self.metadata['CustomerGatewayConfiguration'] = XML(self.metadata['CustomerGatewayConfiguration'])

	# This function will block until the state changes.
	def waitPending(self, client, progress=False):
		while self.metadata['State'] == 'pending':
			sleep(5)
			if progress: print '.',
			sys.stdout.flush()
			self.update(client)
		if progress: print

	def update(self, client):
		client_output = client.describe_vpn_connections(VpnConnectionIds=[self.metadata['VpnConnectionId']])
		if client_output['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		self.parse(client_output['VpnConnections'][0])

	def hasUp(self):
		return self.metadata['VgwTelemetry'][0]['Status'] == 'UP' or self.metadata['VgwTelemetry'][1]['Status'] == 'UP'

	def hasDown(self):
		return self.metadata['VgwTelemetry'][0]['Status'] == 'DOWN' or self.metadata['VgwTelemetry'][1]['Status'] == 'DOWN'

class IpsecConnection:
	name = ''
	conn_prefix = ''
	vpn_connection_id = ''
	vpn_gateway_id = ''
	conn_id = ''
	auto = 'start' if autostart else 'ignore'
	conn_type = 'tunnel'
	secret = ''
	# AWS provided, but implicit:
	#  -'type': ipsec_tunnel/ipsec/mode
	left = dict()
	# AWS provides:
	#  -'left': ipsec_tunnel/vpn_gateway/tunnel_outside_address/ip_address
	#  -'leftsourceip': ipsec_tunnel/vpn_gateway/tunnel_inside_address/ip_address
	# We provide:
	#  -'leftsubnet'
	right = {'right': local_ip}
	# AWS provides:
	#  -'rightsourceip': ipsec_tunnel/customer_gateway/tunnel_inside_address/ip_address
	# We provide:
	#  -'rightsubnet'
	enc_auth = {'authby': 'secret', 'rekey': 'yes', 'keyingtries': '%forever'}
	# AWS provides:
	#  -'phase2': ipsec_tunnel/ipsec/protocol
	#  -'phase2alg': ipsec_tunnel/ipsec/encryption_protocol
	#                                  /authentication_protocol
	#  -'ike': ipsec_tunnel/ike/encryption_protocol
	#                          /authentication_protocol
	#  -'ikelifetime': ipsec_tunnel/ike/lifetime
	#  -'salifetime': ipsec_tunnel/ipsec/lifetime
	#  -'pfs': ipsec_tunnel/ipsec/perfect_forward_secrecy
	#  -'fragmentation': ipsec_tunnel/ipsec/fragmentation_before_encryption
	#  -'mtu': ipsec_tunnel/ipsec/tcp_mss_adjustement - 40
	#    - This shouldn't be touched unless using VTI.
	dpd = {'dpdaction': 'restart'}
	# AWS provides:
	#  -'dpddelay': ipsec_tunnel/ipsec/dead_peer_detection/interval
	#  -'dpdtimeout': ipsec_tunnel/ipsec/dead_peer_detection/retries
	#                 * ipsec_tunnel/ipsec/dead_peer_detection/interval

	def __init__(self, ipsec_output=None, vpc_vpn=None):
		if ipsec_output:
			self.parse(ipsec_output)
		elif vpc_vpn:
			self.configFromVpcVpnConnection(vpc_vpn)

	def __str__(self):
		output = []
		output.append('name == %s' % self.name)
		output.append('conn_prefix == %s' % self.conn_prefix)
		output.append('vpn_connection_id == %s' % self.vpn_connection_id)
		output.append('vpn_gateway_id == %s' % self.vpn_gateway_id)
		output.append('conn_id == %s' % self.conn_id)
		output.append('auto == %s' % self.auto)
		output.append('conn_type == %s' % self.conn_type)
		output.append('secret == %s' % self.secret)
		output.append('left ==\n%s' % pformat(self.left))
		output.append('right ==\n%s' % pformat(self.right))
		output.append('enc_auth ==\n%s' % pformat(self.enc_auth))
		output.append('dpd ==\n%s' % pformat(self.dpd))
		return '\n'.join(output)

	def __hash__(self):
		return hash(self.name)

	def __eq__(self, other):
		# Should probably test for object type.
		return self.name == other.name

	def __ne__(self, other):
		# Should probably test for object type.
		return self.name != other.name

	def __lt__(self, other):
		return NotImplemented

	def __gt__(self, other):
		return NotImplemented

	def __le__(self, other):
		return NotImplemented

	def __ge__(self, other):
		return NotImplemented

	def parse(self, ipsec_output):
		t = ipsec_output.split(':')[1].split(',')

		self.name = t[0].strip().strip('"')
		self.conn_id = t[5].split('=')[1].strip('\'')

		self.conn_prefix, self.vpn_gateway_id, self.vpn_connection_id = self.name.rsplit('_', 2)

	def deleteConfig(self):
		os.remove('/etc/ipsec.d/' + ipsec_conn_prefix + '.conf')

	def deleteSecret(self):
		os.remove('/etc/ipsec.d/' + ipsec_conn_prefix + '.secrets')

	def writeConfig(self):
		conf = []
		conf.append('conn %s' % self.name)
		conf.append('\tauto=%s' % self.auto)
		conf.append('\ttype=%s' % self.conn_type)
		conf.append('\t%s' % '\n\t'.join(map(lambda a: '='.join(a), self.left.items())))
		conf.append('\t%s' % '\n\t'.join(map(lambda a: '='.join(a), self.right.items())))
		conf.append('\t%s' % '\n\t'.join(map(lambda a: '='.join(a), self.enc_auth.items())))
		conf.append('\t%s' % '\n\t'.join(map(lambda a: '='.join(a), self.dpd.items())))
		with open('/etc/ipsec.d/' + ipsec_conn_prefix + '.conf', 'w+') as f:
			f.write('\n'.join(conf) + '\n')

	def writeSecret(self):
		with open('/etc/ipsec.d/' + ipsec_conn_prefix + '.secrets', 'w+') as f:
			f.write(' '.join([self.left['left'], local_ip, ':', 'PSK', '"' + self.secret + '"']) + '\n')

	def configFromVpcVpnConnection(self, vpc_vpn):
		# TODO: VpcVpnConnection and IpsecConnection should probably have a defined interface for this rather than IpsecConnection understanding the VpcVpnConnection metadata structure.
		cgw_config = vpc_vpn.metadata['CustomerGatewayConfiguration']

		# Find an available VPN ipsec tunnel.
		ipsec_tunnel_ip = [ep['OutsideIpAddress'] for ep in vpc_vpn.metadata['VgwTelemetry'] if ep['Status'] == 'DOWN'][0]
		ipsec_tunnel_xpath = './ipsec_tunnel/vpn_gateway/tunnel_outside_address/[ip_address=\'%s\']/../..' % ipsec_tunnel_ip

		# Extract and interprate configuration parameters.
		self.conn_prefix = ipsec_conn_prefix
		self.vpn_connection_id = cgw_config.get('id')
		self.vpn_gateway_id = cgw_config.find('./vpn_gateway_id').text
		self.name = '_'.join([self.conn_prefix, self.vpn_gateway_id, self.vpn_connection_id])

		self.secret = cgw_config.find('%s/ike/pre_shared_key' % ipsec_tunnel_xpath).text

		self.left['left'] = ipsec_tunnel_ip
		self.left['leftsourceip'] = cgw_config.find('%s/vpn_gateway/tunnel_inside_address/ip_address' % ipsec_tunnel_xpath).text
		self.left['leftsubnet'] = vpc_vpn_subnet

		self.right['rightsourceip'] = cgw_config.find('%s/customer_gateway/tunnel_inside_address/ip_address' % ipsec_tunnel_xpath).text
		self.right['rightsubnet'] = ipsec_subnet

		self.enc_auth['phase2'] = cgw_config.find('%s/ipsec/protocol' % ipsec_tunnel_xpath).text
		enc = encLookup[cgw_config.find('%s/ipsec/encryption_protocol' % ipsec_tunnel_xpath).text]
		auth = authLookup[cgw_config.find('%s/ipsec/authentication_protocol' % ipsec_tunnel_xpath).text]
		self.enc_auth['phase2alg'] = '-'.join([enc, auth])
		enc = encLookup[cgw_config.find('%s/ike/encryption_protocol' % ipsec_tunnel_xpath).text]
		auth = authLookup[cgw_config.find('%s/ike/authentication_protocol' % ipsec_tunnel_xpath).text]
		self.enc_auth['ike'] = '-'.join([enc, auth])
		self.enc_auth['ikelifetime'] = cgw_config.find('%s/ike/lifetime' % ipsec_tunnel_xpath).text
		self.enc_auth['salifetime'] = cgw_config.find('%s/ipsec/lifetime' % ipsec_tunnel_xpath).text
		self.enc_auth['pfs'] = pfsLookup[cgw_config.find('%s/ipsec/perfect_forward_secrecy' % ipsec_tunnel_xpath).text]
		self.enc_auth['fragmentation'] = 'yes' if cgw_config.find('%s/ipsec/fragmentation_before_encryption' % ipsec_tunnel_xpath).text == 'true' else 'no'
		self.dpd['dpddelay'] = cgw_config.find('%s/ipsec/dead_peer_detection/interval' % ipsec_tunnel_xpath).text
		self.dpd['dpdtimeout'] = str(\
		  int(cgw_config.find('%s/ipsec/dead_peer_detection/retries' % ipsec_tunnel_xpath).text) \
		  * int(cgw_config.find('%s/ipsec/dead_peer_detection/interval' % ipsec_tunnel_xpath).text))

	def replace(self, write_configs=False):
		if write_configs:
			self.writeConfig()
			self.writeSecret()
		subprocess.call(['ipsec', 'auto', '--replace', self.name])
		subprocess.call(['ipsec', 'auto', '--rereadsecrets'])

	def delete(self):
		subprocess.call(['ipsec', 'auto', '--delete', self.name])

		with open('/etc/ipsec.d/' + ipsec_conn_prefix + '.conf', 'r') as f:
			rightsourceip = [l for l in f.readlines() if 'rightsourceip' in l][0].split('=')[1].strip()
			dev = [l for l in subprocess.check_output(['ip', 'address']).split('\n') if rightsourceip in l][0].split()[-1]
			print ' '.join(['ip', 'address', 'delete', rightsourceip + '/32', 'dev', dev])
			subprocess.call(['ip', 'address', 'delete', rightsourceip + '/32', 'dev', dev])

		self.deleteConfig()
		self.deleteSecret()
		subprocess.call(['ipsec', 'auto', '--rereadsecrets'])

	def up(self, write_configs=False):
		# No attempt is made to ensure that the connection is actually active. Keying errors, routing errors, remote unreachable, etc. will all be ignored.
		if write_configs:
			self.replace(write_configs)
		subprocess.call(['ipsec', 'auto', '--start', self.name])


# Get the public IP according to public service(s). This is a seperate function so that it can query multiple provides if desired.
def get_public_ip():
	from httplib import HTTPConnection, HTTPSConnection

	h = HTTPConnection('checkip.amazonaws.com')
	h.request('GET', '/')
	res = h.getresponse()
	if res.status == 200:
		return res.read().strip()

## Borrowed from https://stackoverflow.com/a/6556951
#def get_default_route_linux():
#	"""Read the default route directly from /proc."""
#	with open("/proc/net/route") as fh:
#		for line in fh:
#			fields = line.strip().split()
#			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
#				continue
#
#			return fields

def getStatus(client):
	# Check for a defined connection in AWS for this host/site.
	vpn_conns = client.describe_vpn_connections(Filters=[{'Name': 'tag:' + tag_key, 'Values': [tag_value]}])
	if vpn_conns['ResponseMetadata']['HTTPStatusCode'] != 200:
		sys.exit(8)

	vpn_conns = map(lambda b: VpcVpnConnection(b), vpn_conns['VpnConnections'])
	vpn_conns = [c for c in vpn_conns if c.metadata['State'] != 'deleted']
	
	cgws = client.describe_customer_gateways(Filters=[{'Name': 'tag:' + tag_key, 'Values': [tag_value]}, {'Name': 'ip-address', 'Values': [public_ip]}])
	if cgws['ResponseMetadata']['HTTPStatusCode'] != 200:
		sys.exit(8)

	cgws = map(lambda b: VpcCgw(b), cgws['CustomerGateways'])
	cgws = [g for g in cgws if g.metadata['State'] != 'deleted']

	# Collect the local IPSec status.
	ipsec_conns = subprocess.check_output(['ipsec', 'whack', '--trafficstatus']).splitlines()
	# Reduce duplicate connections that may appear during rekeying.
	ipsec_conns = set(map(lambda b: IpsecConnection(b), ipsec_conns))
	# We're only interested in connections related to this instatiation of the script.
	ipsec_conns = [c for c in ipsec_conns if c.conn_prefix == ipsec_conn_prefix]

	# If multiples are defined anywhere, manual resolution will be required.
	if len(cgws) > 1:
		print 'Multiple Customer Gateways are defined in AWS. Resolve the issue manually.'
		sys.exit(6)

	if len(vpn_conns) > 1:
		print 'Multiple connections are defined in AWS. Resolve the issue manually.'
		sys.exit(2)
	
	if len(ipsec_conns) > 1:
		print 'Multiple connections are active in IPSec. Resolve the issue manually.'
		pprint(ipsec_conns)
		sys.exit(2)

	return cgws, vpn_conns, ipsec_conns

def help():
	print '%s: This script automates the creation and deletion of VPC VPN connections.' % sys.argv[0]
	print
	print 'Usage:'
	print '\t%s [connect|disconnect|destroy|status|help]' % sys.argv[0]
	print
	print 'Configurations are made in the top of the script.'

def connect(client):
	# Get connection information.
	cgws, vpn_conns, ipsec_conns = getStatus(client)

	# Find or create the Customer Gateway.
	# Should CGW's that have the same tag, but different IP be deleted? This could clean up from old public IP's, but may result in destroying a legitimate connection that was tagged inappropriately.
	if not cgws:
		print 'Creating Customer Gateway.'
		cgws = [VpcCgw()]
		cgws[0].create(client, public_ip, [{'Key': tag_key, 'Value': tag_value}])

	if cgws[0].metadata['State'] != 'available':
		print 'The Customer Gateway state is not \'available\'. Check the CGW.'
		sys.exit(6)

	# Create a VPC VPN connection.
	if not vpn_conns:
		# Confirm the VGW exists.
		vgws = client.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
		if vgws['ResponseMetadata']['HTTPStatusCode'] != 200:
			sys.exit(8)

		if len(vgws['VpnGateways']) != 1:
			print 'The VPN Gateway ID appears to be incorrect.'
			sys.exit(5)
		
		if vgws['VpnGateways'][0]['State'] != 'available':
			print 'The VPN Gateway state is not \'available\'. Check the VGW.'
			sys.exit(5)

		print 'Creating VPN connection.'
		vpn_conns = [VpcVpnConnection()]
		# Create connection.
		vpn_conns[0].create(client, vgw_id, cgws[0], True, [{'DestinationCidrBlock': ipsec_subnet}, {'DestinationCidrBlock': vpc_vpn_subnet}], [{'Key': tag_key, 'Value': tag_value}])

	else:
		# If we have an active connection, confirm it is correct.
		if vpn_conns[0].metadata['VpnGatewayId'] != vgw_id:
			print 'Existing connection in AWS is associated with the wrong VGW.'
			sys.exit(3)
	
		# Confirm existing VPN configuration has correct CGW.
		# If not, we should probably delete it and create the correct one, but risk breaking a working connection.
		if vpn_conns[0].metadata['CustomerGatewayId'] != cgws[0].metadata['CustomerGatewayId']:
			print 'Existing connection in AWS is associated with the wrong CGW.'
			sys.exit(3)

	# Check the state of the VPN connection.
	if vpn_conns[0].metadata['State'] == 'pending':
		vpn_conns[0].waitPending(client)

	if vpn_conns[0].metadata['State'] != 'available':
		print 'VPN connection %s is not available. Resolve the issue manually.' % vpn_conns[0].metadata['VpnConnectionId']
		sys.exit(7)
	
	# Check existing connection definitions.
	if ipsec_conns and ipsec_conns[0].vpn_connection_id == vpn_conns[0].metadata['VpnConnectionId']:
		# Is there any reason to check if AWS thinks it's up?
		print 'Connection exists.'
		sys.exit(0)
	elif ipsec_conns:
		print 'Connections defined on both ends, but don\'t match. Resolve the issue manually.'
		sys.exit(3)
	
	# Defined connection, but not active.
	if vpn_conns[0].hasDown():
		new_ipsec_conn = IpsecConnection(vpc_vpn = vpn_conns[0])
		# Load (replace) configurations in pluto (ipsec whack).
		# Up the connection in pluto.
		if use_files:
			new_ipsec_conn.up(write_configs=True)
		else:
			new_ipsec_conn.up()

	else:
		print 'VPC side of VPN is full. All endpoints are in use.'
		sys.exit(4)

def disconnect(client):
	# TODO: write me
	print 'This feature is not yet implemented.'
	sys.exit()

def destroy(client):
	# Get connection information.
	cgws, vpn_conns, ipsec_conns = getStatus(client)

	# TODO: If the connection isn't active, the configuration files will be left behind. Assuming the connection was configured to start automatically, Libreswan will attempt to connect the next time it starts.
	for i in ipsec_conns:
		i.delete()

	for v in vpn_conns:
		v.destroy(client)

	for c in cgws:
		c.destroy(client)

def status(client):
	# TODO: write me
	print 'This feature is not yet implemented.'
	sys.exit()

if __name__ == '__main__':
	# Before doing anything, let's check the syntax.
	if len(sys.argv) != 2 or sys.argv[1] not in ['connect', 'disconnect', 'destroy', 'status']:
		help()
		sys.exit(1)

	public_ip = get_public_ip()
	ec2_client = boto3.client('ec2', region)
	
	if sys.argv[1] == 'connect':
		connect(ec2_client)
	elif sys.argv[1] == 'disconnect':
		disconnect(ec2_client)
	elif sys.argv[1] == 'destroy':
		destroy(ec2_client)
	elif sys.argv[1] == 'status':
		status(ec2_client)
	else:
		# This should never execute.
		help()
		sys.exit(1)
