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

local transactionVersion     = ProtoField.uint8( "ipbus.trans.version", "Transaction Version", base.DEC, nil, 0xF0)
local transactionID          = ProtoField.uint16("ipbus.trans.id",      "Transaction ID",      base.DEC, nil, 0x0FFF)
local transactionWords       = ProtoField.uint8( "ipbus.trans.words",   "Transaction Words",   base.DEC)
local transactionType        = ProtoField.uint8( "ipbus.trans.type",    "Transaction Type",    base.HEX, nil, 0xF0)
local transactionInfo        = ProtoField.uint8( "ipbus.trans.info",    "Transaction Info",    base.HEX, nil, 0x0F)
local dataWord               = ProtoField.uint32("ipbus.trans.dword",   "Data Word",           base.HEX)
local transactionBaseAddress = ProtoField.uint32("ipbus.trans.baddr",   "Base Address",        base.HEX)

ipbusProto.fields = {
    protoVersion, packetID, endiannessInfo, packetType,
    transactionVersion, transactionID, transactionWords, transactionType, transactionInfo,
    transactionBaseAddress, dataWord
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
        typeID = tvb:range(0,1):bitfield(4,0)
    else
        typeID = tvb:range(7,1):bitfield(0,4)
    end

    local pktType = packetTypes[typeID]
    if pktType == nil then return "Reserved", -1 end

    return pktType, typeID
end

-- Return the number of bytes making up the transaction
function parseReadTransaction(tvb, pktTree, iCode, words)
    if iCode == 0xf then
        pktTree:add_le(transactionBaseAddress, tvb:range(4,4))
    elseif iCode == 0x0 then
        local dataSubtree = pktTree:add(ipbusProto, tvb(4), "Data Words")
        for i = 0, words - 1, 1 do
            dataSubtree:add_le(dataWord, tvb:range(4 + 4 * i, 4))
        end
    end
end

function parseWriteTransaction(tvb, pktTree, iCode, words)
    if iCode == 0xf then
        pktTree:add_le(transactionBaseAddress, tvb:range(4,4))

        local dataSubtree = pktTree:add(ipbusProto, tvb(8), "Data Words")
        for i = 0, words - 1, 1 do
            dataSubtree:add_le(dataWord, tvb:range(8 + 4 * i, 4))
        end
    end
end

-- Get current transaction size in bytes
function getTransactionSize(tvb)
    local tType = tvb:range(0,1):bitfield(0,4)
    local iCode = tvb:range(0,1):bitfield(4,4)
    local words = tvb:range(1,1):uint()

    -- print("getSize(): tType " .. tType .. " iCode " .. iCode .. " words " .. words)

    -- Take into account the common header
    local sizeAcc = 4

    -- TODO: clean this up with a table
    if tType == 0x0 then
        if iCode == 0xf then
            return sizeAcc + 4
        elseif iCode == 0x0 then
            return sizeAcc + words * 4
        end
    elseif tType == 0x1 then
        if iCode == 0xf then
            return sizeAcc + 4 + words * 4
        elseif iCode == 0x0 then
            return sizeAcc
        end
    end

    -- We shouldn't be here!
    return -1
end

function parseTransaction(tvb, pktTree)
    local tType = tvb:range(0,1):bitfield(0,4)
    local iCode = tvb:range(0,1):bitfield(4,4)
    local words = tvb:range(1,1)

    -- print("parseTransaction(): tType " .. tType .. " iCode " .. iCode .. " words " .. words)

    -- Transaction header parsing
    pktTree:append_text(" - " .. transactionTypes[tType] .. ite(iCode == 0xF, " Request", " Reply"))
    pktTree:add_le(transactionVersion, tvb:range(3,1))
    pktTree:add_le(transactionID, tvb:range(2,2))
    pktTree:add_le(transactionWords, words)
    pktTree:add_le(transactionType, tvb:range(0,1)):append_text(" ( " .. transactionTypes[tType] .. " )")
    pktTree:add_le(transactionInfo, tvb:range(0,1)):append_text(" ( " .. infoCodes[iCode] .. " )")

    -- Transaction body
    if tType == 0x0 then
        parseReadTransaction(tvb, pktTree, iCode, words:uint())
    elseif tType == 0x1 then
        parseWriteTransaction(tvb, pktTree, iCode, words:uint())
    end
end

function ipbusProto.dissector(tvb, pinfo, tree)
    local length = tvb:len()
    if length == 0 then return end

    -- print(tvb:len())

    pinfo.cols.protocol = ipbusProto.name

    local subtree = tree:add(ipbusProto, tvb(), "IPbus Protocol Data")
    local headerSubtree = subtree:add(ipbusProto, tvb(0,4), "Header")

    -- Detect endianness based on the position of the byte-order qualifier
    local isLittleEndian = false
    if tvb:range(3,1):bitfield(4,4) == 2 then
        headerSubtree:add(endiannessInfo, "BIG ENDIAN]")
        subtree:add(ipbusProto, tvb(pktBufferOffset), "[ Big endian messages not currently supported... ]")
        return
    elseif tvb:range(0,1):bitfield(0,4) == 0xF then
        isLittleEndian = true
    else
        subtree:add_proto_expert_info(wrongEndianness, "Didn't find the byte-order qualifier...")
        return
    end

    -- Let's parse a little-endian message!
    headerSubtree:add_le(protoVersion, tvb:range(3,1))
    headerSubtree:add_le(packetID, tvb:range(1,2))
    headerSubtree:add_le(packetType, tvb:range(0,1)):append_text(" ( " .. packetTypes[tvb:range(0,1):bitfield(4,0)] .. " )")
    headerSubtree:add(endiannessInfo, "LITTLE ENDIAN]")

    packetTypeName, packetTypeID = getPacketType(tvb, isLittleEndian)

    headerSubtree:append_text(" - " .. packetTypeName)

    -- Simply advance the offset past the header
    local pktBufferOffset = 4

    -- We only support control packets for now...
    if packetTypeID == 0x0 then
        local transactionsSubtree = subtree:add(ipbusProto, tvb:range(pktBufferOffset, -1), "Transactions")
        local transactionCount = 0

        while tvb:reported_length_remaining(pktBufferOffset) ~= 0 do
            local transactionSize = getTransactionSize(tvb:range(pktBufferOffset, -1))

            if transactionSize == -1 then
                return
            end

            parseTransaction(
                tvb:range(pktBufferOffset, transactionSize),
                transactionsSubtree:add(ipbusProto, tvb:range(pktBufferOffset, transactionSize),
                "Transaction " .. transactionCount)
            )

            transactionCount = transactionCount + 1
            pktBufferOffset = pktBufferOffset + transactionSize
        end
    else
        subtree:add(ipbusProto, tvb(pktBufferOffset), "[ Non-control packet decoding is not supported... ]")
    end
end

local updTable = DissectorTable.get("udp.port")
updTable:add(50001, ipbusProto)
