# Sensitive keywords and severity mapping extracted from DorkDigger
from typing import List, Dict

SENSITIVE_KEYWORDS: List[str] = [
  "password", "passwd", "pwd", "pass", "secret", "secrets", "credential", "credentials",
  "apikey", "api_key", "api-token", "api_token", "token", "access_token", "auth_token",
  "auth", "authorization", "bearer", "jwt", "sessionid", "session_id", "oauth", "oauth_token",
  "client_secret", "client_id", "client-id", "client-secret",

  "id_rsa", "id_dsa", "private_key", "privatekey", "ssh_key", "ssh-key", "pem", "ppk",
  "key.pem", "server.key", "ssl.key", "tls.key", "certificate", "crt", "csr",

  ".env", "env", "env.local", ".env.local", "wp-config.php", "config.php", "configuration.php",
  "settings.php", "appsettings.json", "web.config", "database.yml", "application.properties",
  "application.yml", "secrets.yml", "settings.json", "local.php",

  "backup", "backup.sql", "backup.zip", "dump.sql", "database.sql", "dump", "sql", "db_backup",
  "db.sql", "mysqldump", "pg_dump", "mongoexport", "mongodump", "bkp", "bak", "old", "archive",

  "log", "logs", "error_log", "access.log", "apache_log", "nginx_log", "debug.log",
  ".log", ".old", ".tmp", ".temp", "trace", "stacktrace", "core",

  "credentials.json", "authorized_keys", ".htpasswd", ".htaccess", "docker-compose.yml",
  "dockerfile", "docker-compose.override.yml", "kubernetes", "k8s", "secrets", "secret.yaml",
  "helm", "values.yaml", "azure-pipelines.yml", "circleci", ".gitlab-ci.yml", ".travis.yml",

  "aws_access_key_id", "aws_secret_access_key", "aws_credentials", "aws_token",
  "azure_client_id", "azure_client_secret", "azure_subscription", "gcp_credentials",
  "google_api_key", "gcp_key", "service-account.json", "service-account", "google_service_account",

  ".git", ".git/config", ".git-credentials", ".gitignore", "id_rsa.pub", "private.pem",
  "credentials_store", "history", ".ssh", ".ssh/config", "authorized_keys",

  "passwd", "/etc/passwd", "/etc/shadow", "shadow", "pw", "passwords", "passwords.txt",
  ".bash_history", "bash_history", ".zsh_history", "history.log",

  "ci_token", "ci_secret", "deploy_key", "deployment_key", "jenkins", "jenkins_credentials",
  "jenkins_home", "ansible_vault", "vault_password", "vsts", "git-credentials",

  "credit_card", "card_number", "cc_number", "cvv", "cvv2", "expiry_date", "cardholder",
  "social_security", "ssn", "national_id", "id_number", "iban", "bank_account", "routing_number",

  "admin", "administrator", "login", "signin", "signup", "register", "dashboard", "console",
  "manage", "management", "controlpanel", "cpanel", "phpmyadmin", "pma", "adminer",

  "config", "configuration", "install.php", "install", "setup", "setup.php", "upgrade.php",
  "change_password", "reset_password", "forgot_password", "forgot", "restore",

  "mail", "smtp", "smtp_auth", "smtp_password", "mail.log", "email_credentials", "sendgrid",
  "mailgun", "postfix", "exim", "exchange", "imap", "pop3",

  "users.csv", "users.sql", "userlist", "user_data", "userdata", "profiles", "profile.csv",

  "erp", "sap", "oracle", "siebel", "salesforce", "crm", "hr", "payroll", "timesheet",

  "invoice", "invoices", "receipt", "receipts", "contract", "contracts", "agreement", "nda",
  "statement", "statements", "financial", "finances", "tax", "taxes", "paystub",

  "openssl", "gpg", "pgp", "gpg_private", "gpg_key", "pgp_key", ".gpg", ".asc", "pgp.asc",

  ".env.example", ".env.backup", "config.bak", "settings.bak", "credentials.bak", "secret.bak",
  "*.backup", "*.sql.gz", "*.sql.zip", "*.tar.gz",

  "pentest", "pentest_results", "vulnerabilities", "vuln", "exploit", "proof_of_concept",
  "poc", "scanner", "nmap", "nessus", "burpsuite", "burp", "metasploit",

  "mobileprovision", ".mobileprovision", "ipa", "apk", "keystore", ".keystore", "jks",

  "كلمة_المرور", "كلمة المرور", "باسورد", "باسوردات", "مفتاح", "مفاتيح", "سر", "سرّي",
  "مفتاح_خاص", "خصوصي", "شهادة", "نسخة_احتياطية", "نسخة_بكاب", "سجل", "لوق", "لوغ",

  "intext:password", "intext:passwd", "intext:passwords", "filetype:env", "filetype:sql",
  "filetype:log", "filetype:json", "filetype:bak", "filetype:zip", "filetype:tgz",
  "intitle:index.of", "ext:env", "ext:sql", "ext:bak", "ext:zip", "ext:old",

  "backup-old", "backup1", "backup2", "old_backup", "old-version", "old_site", "site_backup",
  "staging", "staging_db", "staging_backup", "test", "test_db", "dev", "development",

  "/.env", "/backup", "/backups", "/db", "/database", "/dump", "/dumps", "/wp-content/uploads",
  "/uploads", "/uploads_backup", "/.git", "/.svn", "/.hg",

  "/api/docs", "/swagger", "/swagger.json", "/openapi", "/redoc", "swagger-ui", "api-docs",
  "graphql", "/graphql", "introspection", "playground",

  "credentials.txt", "keys.txt", "secret.txt", "secrets.txt", "private.txt", "private_keys.txt",

  "rds-combined-ca-bundle", "aws-metadata", "ec2-credentials", "instance-identity", "meta-data",
  "metadata", "meta-data", "vm_password", "root_password", "root_pass", "administrator_password",

  "backup.tar.gz", "site_backup.tar.gz", "joomla.sql", "drupal.sql", "magento.sql",

  "stack dump", "exception", "fatal error", "uncaught exception", "traceback",

  "internal", "internal-api", "internal_docs", "private_api", "hidden", "confidential", "restricted",

  "service_key", "service_key.json", "keyfile", "credentials.yml", "secret_key_base", "master.key",

  "leaked", "leak", "dumped", "exposed", "exposure", "hidden_files", "open_file",
]

# Severity color mapping (termcolor names)
SEVERITY_COLOR: Dict[str, str] = {
    "critical": "red",
    "high": "yellow",
    "medium": "magenta",
    "low": "white",
}

# Build a SEVERITY_MAP dictionary using lists grouped by level
SEVERITY_MAP: Dict[str, str] = {}

def add_words(words: List[str], level: str):
    for w in words:
        SEVERITY_MAP[w.lower()] = level

# critical
add_words([
    "aws_secret_access_key","aws_access_key_id","aws_credentials","aws_token",
    "gcp_credentials","google_api_key","gcp_key","service-account.json","service-account",
    "google_service_account","master.key","secret_key_base","id_rsa","private_key","privatekey",
    "ssh_key","ssh-key","server.key","tls.key","credentials.json",".env",".env.local","wp-config.php",
    "database.sql","dump.sql","backup.sql","mongoexport","mongodump","client_secret","jwt","oauth_token",
    "service_key","service_key.json","keyfile","credentials.yml"
], "critical")

# high
add_words([
    "password","passwd","pwd","pass","secrets","secret","credential","credentials",
    "apikey","api_key","api-token","api_token","token","access_token","auth_token","auth","authorization",
    "bearer","sessionid","session_id","oauth","client_id","client-id","client-secret",
    "pem","ppk","key.pem","ssl.key","crt","csr","authorized_keys","private.pem",
    "credentials_store",".htpasswd","ci_token","ci_secret","deploy_key","deployment_key","vault_password",
    "git-credentials","jenkins_credentials","jenkins_home","ansible_vault","vsts",
    "credit_card","card_number","cc_number","cvv","cvv2","expiry_date","cardholder","social_security",
    "ssn","iban","bank_account","routing_number",
    "/etc/shadow","passwords","passwords.txt",".bash_history","bash_history",".zsh_history","history.log",
    "vm_password","root_password","root_pass","administrator_password"
], "high")

# medium
add_words([
    "settings.php","appsettings.json","web.config","database.yml","application.properties",
    "application.yml","secrets.yml","settings.json","local.php","config.php","configuration.php",
    "azure_client_id","azure_client_secret","azure_subscription",
    "azure-pipelines.yml","circleci",".gitlab-ci.yml",".travis.yml","docker-compose.yml","dockerfile",
    "docker-compose.override.yml","kubernetes","k8s","helm","values.yaml","jenkins",
    "admin","administrator","login","signin","signup","register","dashboard","console","manage",
    "management","controlpanel","cpanel","phpmyadmin","pma","adminer",
    "mail","smtp","smtp_auth","smtp_password","mail.log","email_credentials","sendgrid","mailgun",
    "postfix","exim","exchange","imap","pop3",
    "users.csv","users.sql","userlist","user_data","userdata","profiles","profile.csv",
    "openssl","gpg","pgp","gpg_private","gpg_key","pgp_key",".gpg",".asc","pgp.asc",
    "/api/docs","/swagger","/swagger.json","/openapi","/redoc","swagger-ui","api-docs",
    "graphql","/graphql","introspection","playground","sql",
    "/.env","/.git","/.svn","/.hg","/db","/database","/dump","/dumps","/wp-content/uploads","/uploads","/uploads_backup",
], "medium")

# low
add_words([
    "env","config","configuration","install.php","install","setup","setup.php","upgrade.php",
    "backup","backup.zip","dump","db_backup","db.sql","mysqldump","pg_dump","bkp","bak","old","archive",
    "log","logs","error_log","access.log","apache_log","nginx_log","debug.log",".log",".old",".tmp",".temp",
    "trace","stacktrace","core",".git",".git/config",".git-credentials",".gitignore","id_rsa.pub",".ssh",".ssh/config",
    "history","/etc/passwd","shadow","pw",
    "erp","sap","oracle","siebel","salesforce","crm","hr","payroll","timesheet",
    "invoice","invoices","receipt","receipts","contract","contracts","agreement","nda","statement","statements",
    "financial","finances","tax","taxes","paystub",
    ".env.example",".env.backup","config.bak","settings.bak","credentials.bak","secret.bak",
    "*.backup","*.sql.gz","*.sql.zip","*.tar.gz",
    "pentest","pentest_results","vulnerabilities","vuln","exploit","proof_of_concept","poc","scanner",
    "nmap","nessus","burpsuite","burp","metasploit",
    "mobileprovision",".mobileprovision","ipa","apk","keystore",".keystore","jks",
    "كلمة_المرور","كلمة المرور","باسورد","باسوردات","مفتاح","مفاتيح","سر","سرّي","مفتاح_خاص","خصوصي",
    "شهادة","نسخة_احتياطية","نسخة_بكاب","سجل","لوق","لوغ",
    "intext:password","intext:passwd","intext:passwords","filetype:env","filetype:sql","filetype:log","filetype:json",
    "filetype:bak","filetype:zip","filetype:tgz","intitle:index.of","ext:env","ext:sql","ext:bak","ext:zip","ext:old",
    "backup-old","backup1","backup2","old_backup","old-version","old_site","site_backup","staging","staging_db",
    "staging_backup","test","test_db","dev","development",
    "/backup","/backups",
    "/api/docs","introspection","playground",
    "credentials.txt","keys.txt","secret.txt","secrets.txt","private.txt","private_keys.txt",
    "rds-combined-ca-bundle","aws-metadata","ec2-credentials","instance-identity","meta-data","metadata","meta-data",
    "backup.tar.gz","site_backup.tar.gz","joomla.sql","drupal.sql","magento.sql",
    "stack dump","exception","fatal error","uncaught exception","traceback",
    "internal","internal-api","internal_docs","private_api","hidden","confidential","restricted",
    "service_key","keyfile",
    "leaked","leak","dumped","exposed","exposure","hidden_files","open_file",
], "low")
