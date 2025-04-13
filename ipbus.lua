--[[
Please note this dissector has been built based on:
    - https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
    - https://wiki.wireshark.org/Lua/Dissectors
    - https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
    - https://ipbus.web.cern.ch/doc/user/html/_downloads/d251e03ea4badd71f62cffb24f110cfa/ipbus_protocol_v2_0.pdf
--]]
local ipbusProto = Proto("IPbus", "IPbus Protocol")

local protoVersion   = ProtoField.uint8( "ipbus.version",     "Version",              base.DEC, nil, 0xF0)
local packetID       = ProtoField.uint16("ipbus.packetid",    "Packet ID",            base.DEC)
local endiannessInfo = ProtoField.string("ipbus.endiannesss", "[Detected endianness", base.ASCII)
local packetType     = ProtoField.uint8( "ipbus.type",        "Packet Type",          base.HEX, nil, 0x0F)

local transactionVersion = ProtoField.uint8( "ipbus.trans.version", "Transaction Version", base.DEC, nil, 0xF0)
local transactionID      = ProtoField.uint16("ipbus.trans.id",      "Transaction ID",      base.DEC, nil, 0x0FFF)
local transactionWords   = ProtoField.uint8( "ipbus.trans.words",   "Transaction Words",   base.DEC)
local transactionType    = ProtoField.uint8( "ipbus.trans.type",    "Transaction Type",    base.HEX, nil, 0xF0)
local transactionInfo    = ProtoField.uint8( "ipbus.trans.info",    "Transaction Info",    base.HEX, nil, 0x0F)

local transactionBaseAddress = ProtoField.uint32( "ipbus.trans.read.baddr",    "Base Address",    base.HEX)

ipbusProto.fields = {
    protoVersion, packetID, endiannessInfo, packetType,
    transactionVersion, transactionID, transactionWords, transactionType, transactionInfo,
    transactionBaseAddress
}

local wrongEndianness = ProtoExpert.new("ipbus.endianness", "Wrong endianness", expert.group.DEBUG, expert.severity.WARN)
ipbusProto.experts = { wrongEndianness }

local packetTypes = {
    [0x0] = "Control Packet",
    [0x1] = "Status Packet",
    [0x2] = "Re-send Request Packet",
    [0x3] = "Reserved",
    [0x4] = "Reserved",
    [0x5] = "Reserved",
    [0x6] = "Reserved",
    [0x7] = "Reserved",
    [0x8] = "Reserved",
    [0x9] = "Reserved",
    [0xA] = "Reserved",
    [0xB] = "Reserved",
    [0xC] = "Reserved",
    [0xD] = "Reserved",
    [0xE] = "Reserved",
    [0xF] = "Reserved"
}

local transactionTypes = {
    [0x0] = "Read Transaction",
    [0x1] = "Write Transaction",
    [0x2] = "Non-incrementing Read Transaction",
    [0x3] = "Non-incrementing Write Transaction",
    [0x4] = "Read/Modify/Write Bits Transaction",
    [0x5] = "Read/Modify/Write Sum Transaction",
    [0x6] = "Reserved",
    [0x7] = "Reserved",
    [0x8] = "Reserved",
    [0x9] = "Reserved",
    [0xA] = "Reserved",
    [0xB] = "Reserved",
    [0xC] = "Reserved",
    [0xD] = "Reserved",
    [0xE] = "Reserved",
    [0xF] = "Reserved"
}

local infoCodes = {
    [0x0] = "Request Handled Successfully by Target",
    [0x1] = "Bad Header",
    [0x2] = "Reserved",
    [0x3] = "Reserved",
    [0x4] = "Bus Error on Read",
    [0x5] = "Bus Error on Write",
    [0x6] = "Bus Timeout on Read",
    [0x7] = "Bus Timeout on Write",
    [0x8] = "Reserved",
    [0x9] = "Reserved",
    [0xA] = "Reserved",
    [0xB] = "Reserved",
    [0xC] = "Reserved",
    [0xD] = "Reserved",
    [0xE] = "Reserved",
    [0xF] = "Outbound Request"
}

function ite(c, t, f)
    if c then return t end
    return f
end

function getPacketType(tvb, littleEndian)
    local typeID = -1

    if littleEndian then
        typeID = tvb:range(4,1):bitfield(0,4)
    else
        typeID = tvb:range(7,1):bitfield(0,4)
    end

    local pktType = packetTypes[typeID]
    if pktType == nil then return "Reserved", -1 end

    return pktType, typeID
end

function parseControlPacket(tvb, pktTree)
    local tType = tvb:range(4,1):bitfield(0,4)
    local iCode = tvb:range(4,1):bitfield(4,4)
    pktTree:append_text(" - " .. transactionTypes[tType] .. ite(iCode == 0xF, " Request", " Reply"))
    pktTree:add_le(transactionVersion, tvb:range(7,1))
    pktTree:add_le(transactionID, tvb:range(6,2))
    pktTree:add_le(transactionWords, tvb:range(5,1))
    pktTree:add_le(transactionType, tvb:range(4,1)):append_text(" ( " .. transactionTypes[tType] .. " )")
    pktTree:add_le(transactionInfo, tvb:range(4,1)):append_text(" ( " .. infoCodes[iCode] .. " )")
    if tType == 0x0 and iCode == 0xF then
        pktTree:add_le(transactionBaseAddress, tvb:range(8,4))
    end
end

function ipbusProto.dissector(tvb, pinfo, tree)
    local length = tvb:len()
    if length == 0 then return end

    print(tvb:len())

    pinfo.cols.protocol = ipbusProto.name

    local subtree = tree:add(ipbusProto, tvb(), "IPbus Protocol Data")
    local headerSubtree = subtree:add(ipbusProto, tvb(0,4), "Header")

    if tvb:range(3,1):bitfield(4,4) == 2 then
        headerSubtree:add(endiannessInfo, "BIG ENDIAN]")
    elseif tvb:range(0,1):bitfield(0,4) == 0xF then
        headerSubtree:add_le(protoVersion, tvb:range(3,1))
        headerSubtree:add_le(packetID, tvb:range(1,2))
        headerSubtree:add_le(packetType, tvb:range(0,1)):append_text(" ( " .. packetTypes[tvb:range(0,1):bitfield(4,0)] .. " )")
        headerSubtree:add(endiannessInfo, "LITTLE ENDIAN]")

        packetTypeName, packetTypeID = getPacketType(tvb, true)

        headerSubtree:append_text(" - " .. packetTypeName)

        local transactionsSubtree = subtree:add(ipbusProto, tvb(5), "Transactions")

        if packetTypeID == 0x0 then
            parseControlPacket(tvb, transactionsSubtree:add(ipbusProto, tvb(5), "Transaction 0"))
        end
    else
        subtree:add_proto_expert_info(wrongEndianness, "Didn't find the byte-order qualifier...")
        return
    end
end

local updTable = DissectorTable.get("udp.port")
updTable:add(50001, ipbusProto)
