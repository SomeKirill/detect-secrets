import re
from typing import Any, Dict, Generator, Optional, Pattern, Set

from ..core.potential_secret import PotentialSecret
from ..util.filetype import determine_file_type
from ..util.filetype import FileType
from .base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet

DENYLIST = (
    # Generic keywords
    'api_?key',
    'auth_?key',
    'service_?key',
    'account_?key',
    'db_?key',
    'database_?key',
    'priv_?key',
    'private_?key',
    'client_?key',
    'db_?pass',
    'database_?pass',
    'key_?pass',
    'password',
    'passwd',
    'pwd',
    'secret',
    
    # Web-related sensitive information
    'api_?token',
    'auth_?token',
    'access_?token',
    'refresh_?token',
    'jwt_?token',
    'session_?id',
    'csrf_?token',
    
    # Encryption-related
    'encryption_?key',
    'cipher_?key',
    'crypt_?key',
    'rsa_?key',
    'aes_?key',
    
    # Database credentials
    'mysql_?user',
    'mysql_?pass',
    'sql_?user',
    'sql_?pass',
    'oracle_?user',
    'oracle_?pass',
    'postgres_?user',
    'postgres_?pass',
    'mongodb_?user',
    'mongodb_?pass',
    'db2_?user',
    'db2_?pass',
    
    # API keys and tokens for specific services
    'twilio_?sid',
    'twilio_?token',
    'sendgrid_?key',
    'stripe_?key',
    'github_?token',
    'google_?api_?key',
    'google_?client_?id',
    'google_?client_?secret',
    'aws_?access_?key',
    'aws_?secret_?key',
    
    # Other common sensitive terms
    'private_?token',
    'access_?key',
    'secret_?key',
    'secret_?token',
    'client_?secret',
    'oauth_?token',
    'bearer_?token',
    'apikey',
    'app_?secret',
    'app_?token',
    'encryption_?secret',
    'encryption_?token',
    'signing_?key',
    'signing_?secret',
    'signing_?token',
    
    # Common usernames
    'admin',
    'root',
    'administrator',
    'user',
    'username',
    'login',
    'userid',
    
    # Common email-related terms
    'email',
    'e_?mail',
    'mail',
    'e_?address',
    'email_?address',
    'mail_?address',
    
    # Common personal identifiers
    'name',
    'first_?name',
    'last_?name',
    'fullname',
    'phone',
    'phone_?number',
    'ssn',
    'social_?security_?number',
    'sin',  # Social Insurance Number
    
    # Financial information
    'credit_?card',
    'credit_?card_?number',
    'ccn',
    'credit_?card_?cvv',
    'credit_?card_?expiry',
    'ccv',  # Credit Card Verification Code
    'ccv2',
    'cvc',  # Credit Verification Code
    'cvc2',
    'cvv',  # Card Verification Value
    
    # Personal identification numbers (PINs)
    'pin',
    'personal_?identification_?number',
    'atm_?pin',
    'debit_?card_?pin',
    
    # Birthdates
    'dob',
    'date_?of_?birth',
    
    # Addresses
    'address',
    'home_?address',
    'billing_?address',
    'postal_?address',
    
    # Health-related information
    'health_?card',
    'health_?insurance_?number',
    'hin',
    'medical_?record_?number',
    'mrn',
    'patient_?id',
    
    # API and service-related terms
    'endpoint',
    'url',
    'uri',
    'webhook',
    'callback',
    'callback_?url',
    
    # File and directory paths
    'path',
    'file_?path',
    'dir_?path',
    'directory_?path',
    'file_?location',
    'dir_?location',
    'directory_?location',
)

# ... (existing code)

# Support for suffix after keyword i.e. password_secure = "value"
DENYLIST_REGEX = r'({denylist}){suffix}'.format(
    denylist=DENYLIST_REGEX,
    suffix=AFFIX_REGEX,
)

# Support for prefix and suffix with keyword, needed for reverse comparisons
# i.e. if ("value" == my_password_secure) {}
DENYLIST_REGEX_WITH_PREFIX = r'{prefix}{denylist}'.format(
    prefix=AFFIX_REGEX,
    denylist=DENYLIST_REGEX,
)

# Support for no quotes around the value i.e. password=p@ssw0rd
DENYLIST_UNQUOTED_REGEX = r'{denylist}(?=\s*[=:])(?!\s*["\'])({secret})'.format(
    denylist=DENYLIST_REGEX,
    secret=SECRET,
)

# Non-greedy match
OPTIONAL_WHITESPACE = r'\s*'
OPTIONAL_NON_WHITESPACE = r'[^\s]{0,50}?'
QUOTE = r'[\'"`]'

# ... (existing code)

REGEX_BY_FILETYPE = {
    FileType.GO: GOLANG_DENYLIST_REGEX_TO_GROUP,
    FileType.OBJECTIVE_C: COMMON_C_DENYLIST_REGEX_TO_GROUP,
    FileType.C_SHARP: COMMON_C_DENYLIST_REGEX_TO_GROUP,
    FileType.C: COMMON_C_DENYLIST_REGEX_TO_GROUP,
    FileType.C_PLUS_PLUS: C_PLUS_PLUS_REGEX_TO_GROUP,
    FileType.CLS: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.JAVA: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.JAVASCRIPT: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.PYTHON: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.SWIFT: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.TERRAFORM: QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
    FileType.YAML: CONFIG_DENYLIST_REGEX_TO_GROUP,
    FileType.CONFIG: CONFIG_DENYLIST_REGEX_TO_GROUP,
    FileType.INI: CONFIG_DENYLIST_REGEX_TO_GROUP,
    FileType.PROPERTIES: CONFIG_DENYLIST_REGEX_TO_GROUP,
    FileType.TOML: CONFIG_DENYLIST_REGEX_TO_GROUP,
    # Add the following line to include detection of unquoted sensitive information
    FileType.UNKNOWN: {DENYLIST_UNQUOTED_REGEX: 1},
}


class KeywordDetector(BasePlugin):
    """
    Scans for secret-sounding variable names.

    This checks if denylisted keywords are present in the analyzed string.
    """
    secret_type = 'Secret Keyword'

    def __init__(self, keyword_exclude: Optional[str] = None) -> None:
        self.keyword_exclude = None
        if keyword_exclude:
            self.keyword_exclude = re.compile(
                keyword_exclude,
                re.IGNORECASE,
            )

    def analyze_string(
        self,
        string: str,
        denylist_regex_to_group: Optional[Dict[Pattern, int]] = None,
    ) -> Generator[str, None, None]:
        if self.keyword_exclude and self.keyword_exclude.search(string):
            return

        if denylist_regex_to_group is None:
            attempts = [
                QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP,
            ]
        else:
            attempts = [denylist_regex_to_group]

        has_results = False
        for denylist_regex_to_group in attempts:
            for denylist_regex, group_number in denylist_regex_to_group.items():
                match = denylist_regex.search(string)
                if match:
                    has_results = True
                    yield match.group(group_number)

            if has_results:
                break

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        filetype = determine_file_type(filename)
        denylist_regex_to_group = REGEX_BY_FILETYPE.get(filetype, QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP)  # noqa: E501
        return super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            denylist_regex_to_group=denylist_regex_to_group,
        )

    def json(self) -> Dict[str, Any]:
        return {
            'keyword_exclude': (
                self.keyword_exclude.pattern
                if self.keyword_exclude
                else ''
            ),
            **super().json(),
        }
