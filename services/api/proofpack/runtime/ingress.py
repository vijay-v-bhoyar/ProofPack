"""Explicit private ALB subnet trust; never infer trust from request headers."""
from dataclasses import dataclass
from ipaddress import IPv4Network


@dataclass(frozen=True)
class IngressConfig:
    mode: str
    trusted_proxy_cidrs: tuple[str, str]

    def __post_init__(self):
        try:
            if (type(self.mode) is not str or self.mode != 'alb'
                    or type(self.trusted_proxy_cidrs) is not tuple or len(self.trusted_proxy_cidrs) != 2):
                raise ValueError()
            private = tuple(IPv4Network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
            networks = []
            for value in self.trusted_proxy_cidrs:
                if type(value) is not str or not 1 <= len(value) <= 18:
                    raise ValueError()
                network = IPv4Network(value, strict=True)
                if (str(network) != value or not 16 <= network.prefixlen <= 27
                        or not any(network.subnet_of(parent) for parent in private)):
                    raise ValueError()
                networks.append(network)
            if networks[0].overlaps(networks[1]):
                raise ValueError()
        except (ValueError,TypeError,AttributeError) as exc:
            raise ValueError('two exact nonoverlapping private IPv4 ALB subnets required') from None


def server_proxy_options(config):
    if config is None:
        return {'proxy_headers':False}
    if type(config) is not IngressConfig:
        raise ValueError('explicit typed ingress configuration required')
    IngressConfig(config.mode, config.trusted_proxy_cidrs)
    # Uvicorn gets an explicit string, never the FORWARDED_ALLOW_IPS environment
    # default. Its installed middleware checks the socket peer against these nets.
    return {'proxy_headers':True, 'forwarded_allow_ips':','.join(config.trusted_proxy_cidrs)}
