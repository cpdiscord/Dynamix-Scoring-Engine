# Dynamix Scoring Engine

The Dynamix Scoring Engine is a simple, public scoring program for fixing security vulnerabilities in a virtual machine image. It is maintained and owned by the CPDiscord Development Team.

> Dynamix is currently under development and has not been officially released.

## To-Do List
- [X] Forensics Questions checking
- [X] Firewall status checking
- [X] Program update checking
- [X] Users
  - [X] Group memberships
  - [X] Attributes (password expires, locked out, disabled)
  - [X] Availability (Do they exist?)
  - [X] Group creation (Does a group exist and are users added to it?)
- [ ] Group Policy
- [ ] Firefox security
- [ ] Filezilla security
- [X] Program is installed or uninstalled
- [ ] IE security
- [X] Add and remove features (Windows Additional Features, Win+R)
- [X] File detection
- [X] Services
- [X] Shares
  - [ ] Share settings
- [ ] Local Security Policy (code is done, still needs to be fully implemented)
- [ ] Hosts file
- [ ] Fully implement engine with scoring report HTML
- [ ] Add a license

## Optional
- [ ] Dynamic checking based on system (PIDs)
- [ ] Critical services (testing if they actually function on a network)
- [ ] Automatically create forensics question.
