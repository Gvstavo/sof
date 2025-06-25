# firewall_lib/dns_data.py
# -*- coding: utf-8 -*-

QTYPE_MAP = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    255: 'ANY'
}

class DNSData:
    """Classe base que define a estrutura de dados para um pacote DNS."""
    def __init__(self):
        self.is_valid: bool = False
        self.id: int = 0
        self.flags: int = 0
        self.qdcount: int = 0
        self.qname: str = ""
        self.qtype: int = 0 # <-- NOVO ATRIBUTO
        self.qclass: int = 0
        self.recursion_desired: bool = False

    def __str__(self) -> str:
        """Retorna uma string formatada representando os dados do pacote DNS."""
        if not self.is_valid:
            return "[Pacote DNS Inválido ou Não Analisado]"
        
        rd_str = "RD" if self.recursion_desired else "!RD"
        qtype_str = QTYPE_MAP.get(self.qtype, str(self.qtype)) # <-- USA O MAPA
        
        return (f"DNS Query | ID: {self.id:<5} | QNAME: {self.qname:<30} "
                f"| QTYPE: {qtype_str:<5} | QCOUNT: {self.qdcount} | FLAGS: [{rd_str}]")