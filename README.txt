Notes:
  Whitepaper and Apple disagree on which bits are stored in the chopped-up byte. Whitepaper says low 5 bits in the first and high 2 in the last, and Apple says high 5 bits in the first and low 2 in the last.

To run this as a non-root user, you need to grant some rights to bluepy-helper. First, find it:
```
find /usr/local/lib -name bluepy-helper
```

Then for each one:
```
sudo setcap 'cap_net_raw,cap_net_admin+eip' <path to bluepy-helper>
```