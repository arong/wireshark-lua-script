
----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 5540, -- default TCP port number for VREP
    max_msg_len  = 65535, -- max length of VREP message
    subdissect   = false, -- whether to call sub-dissector or not
    subdiss_type = wtap.NETLINK, -- the encap we get the subdissector for
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()


--------------------------------------------------------------------------------
-- creates a Proto object, but doesn't register it yet
local vrep = Proto("vrep", "NGOD VREP Protocol(iPanel Flavor)")


----------------------------------------
local OPEN         = 1
local UPDATE       = 2
local NOTIFICATION = 3
local KEEPALIVE    = 4
-- a table of all of our Protocol's fields
local vrep_type = {
	[OPEN]         = "OPEN",
	[UPDATE]       = "UPDATE",
	[NOTIFICATION] = "NOTIFICATION",
	[KEEPALIVE]    = "KEEPALIVE"
}
-- OPEN method optional parameter  encoding
local open_param_type = {
	[1] = "Capability Info",
	[2] = "Streaming Zone",
	[3] = "Component Name",
	[4] = "Vendor specific String"
}
-- open.param.cap
local cap_code = {
	[1] = "Route Type Supported",
	[2] = "Send Receive Capability"
}
-- route type supported
local supported_route = {
	[32769] = "NGOD Name"
}
local application_protocol = {
	[32766] = "Pre-provisioned (None)",
	[32768] = "RTSP (R6 Session Parameter Only)",
	[32769] = "RTSP (R6 Session Parameter and Provisioning)",
	[32770] = "RTSP (R4)",
	[32771] = "A3 (HTTP/XML)",
	[32772] = "R2 (RTSP)",
	[32773] = "S6 (RTSP)",
	[32774] = "S6 (TBD)",
	[32775] = "S4 (RTSP)",
	[32776] = "S3 (RTSP)",

}
local pf_length         = ProtoField.uint16("vrep.length", "Message Length")
local pf_type           = ProtoField.uint8("vrep.type", "Type Code", base.DEC, vrep_type)
local pf_open           = ProtoField.bytes("vrep.open", "Open Method")
local pf_update         = ProtoField.bytes("vrep.update", "Update Method")
local pf_notify         = ProtoField.bytes("vrep.notify", "Notification Method")
local pf_keep           = ProtoField.bytes("vrep.keep", "Keepalive Method")

-- Protocol fields for OPEN method
local pf_version        = ProtoField.uint8("vrep.open.version", "Version")
local pf_reserved1      = ProtoField.uint8("vrep.open.reserved1","reserved")
local pf_hold_time      = ProtoField.uint16("vrep.open.hold_time","Hold Time")
local pf_reserved2      = ProtoField.uint32("vrep.open.reserved2","reserved")
local pf_identifier     = ProtoField.uint32("vrep.open.identifier","VREP Identifier")
local pf_open_param_len = ProtoField.uint16("vrep.open.len","Parameters Length")
local pf_open_parameter = ProtoField.bytes("vrep.open.param", "Optional Parameters")
-- Protocol fields for open parameter
local pf_open_attr_type = ProtoField.uint16("vrep.open.param.type","Parameter Type",base.DEC, open_param_type)
local pf_open_attr_len  = ProtoField.uint16("vrep.open.param.len","Parameter Length")
local pf_open_attr_var  = ProtoField.bytes("vrep.open.param.var","Parameter Value")
local pf_open_attr_cap  = ProtoField.bytes("vrep.open.param.cap","Capability Info")

-- capability info
local pf_cap_code       = ProtoField.uint16("vrep.open.param.cap.code", "Capability Info", base.DEC, cap_code)
local pf_cap_len        = ProtoField.uint16("vrep.open.param.cap.len", "Capability Length")
local pf_cap_var        = ProtoField.uint16("vrep.open.param.cap.var", "Capability Value")
-- route types
local pf_addr_family    = ProtoField.uint16("vrep.open.param.cap.addr_family", "Address Family",base.DEC, supported_route)
local pf_app_proto      = ProtoField.uint16("vrep.open.param.cap.app_proto", "Application Protocol",base.DEC, application_protocol)

-- register the ProtoField
vrep.fields = {
	pf_length,
	pf_type,
	pf_open,
	pf_update,
	pf_notify,
	pf_keep,
	pf_version,
	pf_reserved1,
	pf_hold_time,
	pf_reserved2,
	pf_identifier,
	pf_open_param_len,
	pf_open_parameter,
    pf_open_attr_type,
    pf_open_attr_len,
    pf_open_attr_var,
    pf_open_attr_cap,
    pf_cap_code,
    pf_cap_len,
    pf_cap_var,
    pf_addr_family,
    pf_app_proto,
}

dprint2("VREP ProtoField registered")

-- our function table, handle different message
local h_open, h_update, h_notification, h_keepalive
local fun_table = {
	[OPEN]         = h_open,
	[UPDATE]       = h_update,
	[NOTIFICATION] = h_notification,
	[KEEPALIVE]    = h_keepalive
}
-- open method dissector
local h_cap, h_zone, h_name, h_vendor
local open_dissector = {
	[1] = h_cap,
	[2] = h_zone,
	[3] = h_name,
	[4] = h_vendor,
}
-- update method dissector

-- implementation of above function
-- the return value of all these functions are the number of bytes dissected
h_cap = function(tvbuf, pos, len, root)
	local attr_tvbr   = tvbuf:range(param_offset+2, 2)
	local attr_len    = attr_tvbr:uint()
	local attr_tree   = root:add("Parameter Value")
	local attr_offset = param_offset+4
	if attr_len >0 then
		attr_tree:add(pf_cap_code, tvbuf:range(attr_offset, 2))
		attr_tree:add(pf_cap_len, tvbuf:range(attr_offset + 2, 2))
		local cap_code = tvbuf:range(attr_offset, 2):uint()
		if cap_code == 1 then
			attr_tree:add(pf_addr_family,tvbuf:range(attr_offset+4, 2))
			attr_tree:add(pf_app_proto, tvbuf:range(attr_offset+6, 2))
		end
	end
end

h_zone = function(tvbuf, pos, len, root)

end

h_name = function(tvbuf, pos, len, root)

end

h_vendor = function(tvbuf, pos, len, root)

end

parse_open = function(tvbuf, pos, len, root)
	local pso_cpy = pos
	local subtree = root:add("Open Method")
	subtree:add(pf_version,        tvbuf:range(pos,      1))
	subtree:add(pf_reserved1,      tvbuf:range(pos + 1,  1))
	subtree:add(pf_hold_time,      tvbuf:range(pos + 2,  2))
	subtree:add(pf_reserved2,      tvbuf:range(pos + 4,  4))
	subtree:add(pf_identifier,     tvbuf:range(pos + 8,  4))
	subtree:add(pf_open_param_len, tvbuf:range(pos + 12, 2))
	local param_len = tvbuf:range(pos+12, 2):uint()
	pos = pos + 14
	len = len - 14
	if param_len > 0 then
		local param_tree   = subtree:add("Optional Parameters")
		while param_len > 0 do
			local type_range = tvbuf:range(pos,   2)
			local len_range  = tvbuf:range(pos+2, 2)
			local para_type  = type_range:uint()
			local para_len   = len_range:uint()
			root:add(pf_open_attr_type, type_range)
			root:add(pf_open_attr_len,  len_range)
			local handler = open_dissector[para_type]
			if handler ~= nil then
				handler(tvbuf, pos + 4, para_len, subtree)
			else
				return
			end
		end
	end
end
-- due to a bug in older (prior to 1.12) wireshark versions, we need to keep newly created
-- Tvb's for longer than the duration of the dissect function (see bug 10888)
-- this bug only affects dissectors that create new Tvb's, which is not that common
-- but this VREP dissector happens to do it in order to create the fake SLL header
-- to pass on to the Netlink dissector
local tvbs = {}

---------------------------------------
-- This function will be invoked by Wireshark during initialization, such as
-- at program start and loading a new file
function vrep.init()
    -- reset the save Tvbs
    tvbs = {}
end


-- this is the size of the VREP message header (3 bytes) and the minimum VREP
-- message size we need to figure out how much the rest of the Netlink message
-- will be
local VREP_MSG_HDR_LEN = 3

-- some forward "declarations" of helper functions we use in the dissector
local createSllTvb, dissectVREP, checkVREPLength

-- this holds the Dissector object for Netlink, which we invoke in
-- our VREP dissector to dissect the encapsulated Netlink protocol
local netlink = DissectorTable.get("wtap_encap"):get_dissector(default_settings.subdiss_type)

-- this holds the plain "data" Dissector, in case we can't dissect it as Netlink
local data = Dissector.get("data")


--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "vrep.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function vrep.dissector(tvbuf, pktinfo, root)
    dprint2("vrep.dissector called")
    -- reset the save Tvbs
    tvbs = {}

    -- get the length of the packet buffer (Tvb).
    local pktlen = tvbuf:len()

    local bytes_consumed = 0

    -- we do this in a while loop, because there could be multiple VREP messages
    -- inside a single TCP segment, and thus in the same tvbuf - but our
    -- vrep.dissector() will only be called once per TCP segment, so we
    -- need to do this loop to dissect each VREP message in it
    while bytes_consumed < pktlen do

        -- We're going to call our "dissect()" function, which is defined
        -- later in this script file. The dissect() function returns the
        -- length of the VREP message it dissected as a positive number, or if
        -- it's a negative number then it's the number of additional bytes it
        -- needs if the Tvb doesn't have them all. If it returns a 0, it's a
        -- dissection error.
        local result = dissectVREP(tvbuf, pktinfo, root, bytes_consumed)

        if result > 0 then
            -- we successfully processed an VREP message, of 'result' length
            bytes_consumed = bytes_consumed + result
            -- go again on another while loop
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        else
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        end
    end

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed
end


----------------------------------------
-- The following is a local function used for dissecting our VREP messages
-- inside the TCP segment using the desegment_offset/desegment_len method.
-- It's a separate function because we run over TCP and thus might need to
-- parse multiple messages in a single segment/packet. So we invoke this
-- function only dissects one VREP message and we invoke it in a while loop
-- from the Proto's main disector function.
--
-- This function is passed in the original Tvb, Pinfo, and TreeItem from the Proto's
-- dissector function, as well as the offset in the Tvb that this function should
-- start dissecting from.
--
-- This function returns the length of the VREP message it dissected as a
-- positive number, or as a negative number the number of additional bytes it
-- needs if the Tvb doesn't have them all, or a 0 for error.
local vrep_min_len = 3
dissectVREP = function(tvbuf, pktinfo, root, offset)
    dprint2("VREP dissect function called")

    local length_val, length_tvbr = checkVREPLength(tvbuf, offset)

    if length_val < vrep_min_len then
        return length_val
    end

    -- if we got here, then we have a whole message in the Tvb buffer
    -- so let's finish dissecting it...

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("VREP")

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame/packet, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(pktinfo.cols.info), "^VREP") == nil then
        pktinfo.cols.info:set("VREP")
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(vrep, tvbuf:range(offset, length_val))

    -- dissect the length field
    tree:add(pf_length, length_tvbr)

    -- dissect the type field
    local msgtype_tvbr = tvbuf:range(offset + 2, 1)
    local msgtype_val  = msgtype_tvbr:uint()
    tree:add(pf_type, msgtype_tvbr)
    local handler = fun_table[msgtype_val]
    if handler ~= nil then
    	handler(tvbuf, offset+3, pf_length -3)
    else
    	print("unknown type" .. tostring(msgtype_val))
    end
    return length_val
end


----------------------------------------
-- The function to check the length field.
--
-- This returns two things: (1) the length, and (2) the TvbRange object, which
-- might be nil if length <= 0.
checkVREPLength = function (tvbuf, offset)

    -- "msglen" is the number of bytes remaining in the Tvb buffer which we
    -- have available to dissect in this run
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        dprint2("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if msglen < VREP_MSG_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        dprint2("Need more bytes to figure out VREP length field")
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, then we know we have enough bytes in the Tvb buffer
    -- to at least figure out the full length of this VREP messsage (the length
    -- is the 16-bit integer in third and fourth bytes)

    -- get the TvbRange of bytes 3+4
    local length_tvbr = tvbuf:range(offset, 2)

    -- get the length as an unsigned integer, in network-order (big endian)
    local length_val  = length_tvbr:uint()

    if length_val > default_settings.max_msg_len then
        -- too many bytes, invalid message
        dprint("VREP message length is too long: ", length_val)
        return 0
    end

    if msglen < length_val then
        -- we need more bytes to get the whole VREP message
        dprint2("Need more bytes to desegment full VREP")
        return -(length_val - msglen)
    end

    return length_val, length_tvbr
end


----------------------------------------
-- For us to be able to use Wireshark's built-in Netlink dissector, we have to
-- create a fake SLL layer, which is what this function does.
--
local ARPHRD_NETLINK, WS_NETLINK_ROUTE, emptyBytes

-- in release 1.12+, you could call Tvb:raw() to get the raw bytes, and you
-- can call ByteArray.new() using a Lua string of binary; since that's easier
-- and more efficient, wel;l do that if the Wireshark running this script is
-- 1.12+, otherwise will do the 'else' clause the longer way
if Tvb.raw then
    -- if we're here, this is Wireshark 1.12+, so we can deal with raw Lua binary strings

    -- the "hatype" field of the SLL must be 824 decimal, in big-endian encoding (0x0338)
    ARPHRD_NETLINK = "\003\056"
    WS_NETLINK_ROUTE = "\000\000"

    emptyBytes = function (num)
        return string.rep("\000", num)
    end

    createSllTvb = function (tvbuf, begin, length)
        dprint2("VREP createSllTvb function called, using 1.12+ method")
        -- the SLL header and Netlink message
        local sllmsg =
        {
            emptyBytes(2),           -- Unused 2B
            ARPHRD_NETLINK,          -- netlink type
            emptyBytes(10),          -- Unused 10B
            WS_NETLINK_ROUTE,        -- Route type
            tvbuf:raw(begin, length) -- the Netlink message
        }
        local payload = table.concat(sllmsg)

        return ByteArray.new(payload, true):tvb("Netlink Message")
    end

else
    -- prior to 1.12, the only way to create a ByteArray was from hex-ascii
    -- so we do things in hex-ascii
    ARPHRD_NETLINK = "0338"
    WS_NETLINK_ROUTE = "0000"

    emptyBytes = function (num)
        return string.rep("00", num)
    end

    createSllTvb = function (tvbuf, begin, length)
        dprint2("VREP createSllTvb function called, using pre-1.12 method")

        -- first get a TvbRange from the Tvb, and the TvbRange's ByteArray...
        local nl_bytearray = tvbuf(begin,length):bytes()

        -- then create a hex-ascii string of the SLL header portion
        local sllmsg =
        {
            emptyBytes(2),      -- Unused 2B
            ARPHRD_NETLINK,     -- netlink type
            emptyBytes(10),     -- Unused 10B
            WS_NETLINK_ROUTE    -- Route type
        }
        local hexSLL = table.concat(sllmsg)

        -- then create a ByteArray from that hex-string
        local sll_bytearray = ByteArray.new(hexSLL)

        -- then concatenate the two ByteArrays
        local full_bytearray = sll_bytearray .. nl_bytearray

        -- create the new Tvb from the full ByteArray
        -- and because this is pre-1.12, we need to store them longer to
        -- work around bug 10888
        tvbs[#tvbs+1] = full_bytearray:tvb()

        -- now return the newly created Tvb
        return tvbs[#tvbs]
    end
end


--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(default_settings.port, vrep)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, vrep)
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
vrep.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the VREP dissector is enabled or not")

vrep.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                        "Whether the VREP packet's content" ..
                                        " should be dissected or not")

vrep.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function vrep.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect  = vrep.prefs.subdissect

    default_settings.debug_level = vrep.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= vrep.prefs.enabled then
        default_settings.enabled = vrep.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")
print("hello world!")
