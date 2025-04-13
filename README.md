# A collection of Wireshark dissectors
When working in different projects one sometimes comes across lesser known protocols which don't
have the traction needed to have a full-fledged dissector shipped with Wireshark. When things
don't work the first impulse one usually has is to manually decode information in the payload,
but that'll only take you so far...

At some point it's common to decide a dissector would be quite a bit of help, so we roll our sleeves
up and get to work. Thankfully, Wireshark's design allows for a quite seamless addition of new
dissectors.

Wireshark allows one to write dissectors in two languages: C and Lua. The former is faster, but
the development overhead is much larger. Lua won't be as fast (although it **is** fast), but it's
really easy to whip something up in a shorter timespan. Unless absolutely necessary we'll
develop our dissectors in Lua; besides, the language is quite nice!

## Installing these dissectors
Wireshark is capable of reloading all Lua plugins seamlessly when running: these just need to be placed
in the different plugin folders as documented [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

The general idea is to:

1. Go to `Help –> About Wireshark –> Folders` and find your personal plugins folder so that you can copy Lua scripts there.
1. Reload all the Lua plugins wither with the appropriate menu button or with `Ctrl+Shift+L` (`Cmd+Shift+L` on macOS).

After that, the dissectors should be usable. If there's an error with the code it'll trigger an error window with relevant
information.

## Development resources
Wireshark's development guide offers a wealth of resources tremendously valuable for developing dissectors,
including:

1. [An overview on dissectors written in Lua](https://wiki.wireshark.org/Lua/Dissectors).
1. [An explanation on functions for dissectors](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html).
1. [An explanation on acquiring packet information](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html).
1. [An explanation on functions for handling the packet buffer](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html).
1. [An explanation on adding information to the dissection tree](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html).

The guide on writing a dissector provided by Mika over [here](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html).

Also, bear in mind that you can always rely on the **Lua Console** under the `Tools` menu in the toolbar. You can see information
`print()`ed from Lua scripts there and you can also evaluate any statement in Wiresharks context.

## Available dissectors
### IPbus
The IPbus protocol offers a control link for electronics and is widely used in the context of High Energy Physics. It's commonly
leveraged to interact with the firmware running on FPGAs so that users can read out information and modify memory-mapped resources
whilst the firmware runs. You can access more information on IPbus over [here](https://ipbus.web.cern.ch).

This UPD-based protocol supports both little and big endian byte orderings and sports a reduced-yet-complete collection of messages.

This dissector has been developed as part of the Phase-II Upgrade of the ATLAS Liquid Argon Calorimeter Upgrade for the High-Luminosity
LHC era.

The IPbus protocol specification is available [here](https://ipbus.web.cern.ch/doc/user/html/_downloads/d251e03ea4badd71f62cffb24f110cfa/ipbus_protocol_v2_0.pdf).
