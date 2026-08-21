NXS :: auth-escalation

Post-anomaly privilege / command escalation probe.

After an anomalous response, attempts elevated commands
(FTP SITE/RETR, SMTP VRFY/EXPN, HTTP admin paths).
Exit 2 on elevated success. Reports confidence level.

Intrusive category. Complements auth-bypass.
