# firewall_lib/dns_firewall.py
from typing import Optional, Set, Dict
from .dns_parser import ParsedDNSPacket
from .dns_data import QTYPE_MAP

class DNSFirewall:
    def __init__(self, whitelist: Set[str] = None, blacklist: Set[str] = None, 
                 qtype_rules: Dict = None, # <-- NOVO PARÂMETRO
                 options: Dict = None):
        
        self.whitelist = whitelist or set()
        self.blacklist = blacklist or set()
        self.qtype_rules = qtype_rules or {} # <-- ARMAZENA AS REGRAS DE QTYPE
        self.options = options or {}

        # (O resto do __init__ com a otimização dos wildcards continua o mesmo)
        self._wl_exact = {r for r in self.whitelist if not r.startswith('*')}
        self._wl_wildcard = {r.lstrip('*.') for r in self.whitelist if r.startswith('*')}
        self._bl_exact = {r for r in self.blacklist if not r.startswith('*')}
        self._bl_wildcard = {r.lstrip('*.') for r in self.blacklist if r.startswith('*')}

    def _is_match(self, qname: str, exact_rules: Set[str], wildcard_rules: Set[str]) -> bool:
        # (Este método continua o mesmo)
        if qname in exact_rules: return True
        for wildcard_suffix in wildcard_rules:
            if qname.endswith(wildcard_suffix): return True
        return False

    def check(self, packet: ParsedDNSPacket) -> Optional[str]:
        if not packet.is_valid:
            return "Pacote malformado"

        # Lógica de Precedência: Domínio (WL/BL) -> QTYPE -> Opções
        
        # 1. Checagem da Whitelist de Domínio
        if self._is_match(packet.qname, self._wl_exact, self._wl_wildcard):
            return None 

        # 2. Checagem da Blacklist de Domínio
        if self._is_match(packet.qname, self._bl_exact, self._bl_wildcard):
            return f"Domínio '{packet.qname}' está na blacklist"

        # --- AQUI ESTÁ A NOVA LÓGICA DE FILTRAGEM ---
        # 3. Checagem das Regras de QTYPE
        if self.qtype_rules:
            mode = self.qtype_rules.get('mode', 'blacklist')
            types = self.qtype_rules.get('types', set())
            qtype_str = QTYPE_MAP.get(packet.qtype, str(packet.qtype))
            
            if mode == 'blacklist' and packet.qtype in types:
                return f"QTYPE '{qtype_str}' está na blacklist"
            elif mode == 'whitelist' and packet.qtype not in types:
                return f"QTYPE '{qtype_str}' não está na whitelist"
        # --- FIM DA NOVA LÓGICA ---

        # 4. Checagem de Opções Adicionais
        if self.options.get('require_rd') and not packet.recursion_desired:
            return "Flag 'Recursion Desired' não está ativada"
        
        # ... (outras regras de opções)
        
        return None