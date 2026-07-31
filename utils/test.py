from radix import Radix
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from socket import inet_aton

r = Radix()
r.add("114.114.114.114")
