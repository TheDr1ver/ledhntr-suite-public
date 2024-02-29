# LEDHNTR

\\ ˌel-(ˌ)ē-ˈdē ˈhən-tər \\ Or in simple terms, "El-Ee-Dee Hunter"

Link Every Detail - Heuristic Network Threat Research

LEDHNTR is an attempt to combine data collection, enrichment, and analysis into
a single platform that relies on graph database principles for pivoting.

It currently consists of the core framework (LEDHNTR), various modular plugins
(LEDHNTR-Plugins), and a crappy web UI (LEDMGMT) that makes pivoting and
navigating the results less painful that living in Jupyter Notebooks all day.

## DISCLAIMER

I am an analyst, NOT a dev. Parts of this code base will make that statement obvious.
As such, some (or all) of this code may cease to work at any point in time. I am
working on this codebase entirely in my own free time. As such, while I appreciate
issues or pull requests, my ability to patch/update/debug anything in this
repository will be extremely limited at best..

Use at your own risk. You have been warned.

## INSTALL

See [INSTALL-Docker](https://github.com/TheDr1ver/ledhntr-suite-public/blob/main/docs/INSTALL-Docker.md) to
get up and running quickly with Docker.

See [INSTALL-Local](https://github.com/TheDr1ver/ledhntr-suite-public/blob/main/docs/INSTALL-Local.md) to
install LEDHNTR and your desired plugins on your local machine. This makes it easier
to develop notebooks that can easily interact with the LEDHNTR-Docker instance, OR
may be desirable if you're running something lean that doesn't require a TypeDB database.

## Acknowledgement

Infrastructure was heavily influenced/borrowed from [stoQ](https://github.com/PUNCH-Cyber/stoq/),
I just wanted my framework to be able to do its own automated pivoting and handle
data in a way that's not quite so flat.
