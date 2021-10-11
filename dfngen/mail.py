import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import os
from os.path import basename

def send_mail(send_from, send_to, subject, text, files=None,
              use_sendmail = True,
              server="127.0.0.1"):
    if isinstance(send_to, str):
        send_to = [send_to,]
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    for f in files or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(f)
            )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
        msg.attach(part)

    if use_sendmail:
        sendmail_location = "/usr/sbin/sendmail" # sendmail location
        p = os.popen("%s -t" % sendmail_location, "w")
        p.write(msg.as_string())
        status = p.close()
        if status and status != 0:
            print( f"ERROR: Sendmail exit status {status}")
            return False
        return True
    else:
        s = smtplib.SMTP(host=server)
        try:
            # FIXME: if multiple recipients, we should check the return value
            ret = s.sendmail(send_from, send_to, msg.as_string())
            s.quit()
            return ret
        except:
            pass
        return False

