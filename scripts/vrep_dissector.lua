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
        debug_level = DEBUG,
        enabled = true, -- whether this dissector is enabled or not
        port = 5540, -- default TCP port number for VREP
        max_msg_len = 65535, -- max length of VREP message
        subdissect = false, -- whether to call sub-dissector or not
        subdiss_type = wtap.NETLINK, -- the encap we get the subdissector for
    }


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}, " "))
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
    [1] = "OPEN",
    [2] = "UPDATE",
    [3] = "NOTIFICATION",
    [4] = "KEEPALIVE"
}

-- OPEN method optional parameter  encoding
local open_param_type = {
    [1] = "Capability Info",
    [2] = "Streaming Zone",
    [3] = "Component Name",
    [4] = "Vendor Specific Info"
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

-- application protocol
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
-- send receive ability
local rend_recv_ability = {
    [1] = "send receive mode",
    [2] = "send only mode",
    [3] = "receive only mode"
}

-- attribute flags, 0 is well-known, otherwise unknown
local attr_flags = {
    [0] = "Well-Known Flags",
}

-- CAS type
local cas_type = {
    [0] = "None",
    [1] = "Non-Session",
    [3] = "Session",
}

-- encryption scheme
local enc_scheme = {
    [0] = "DES",
    [1] = "3DES",
    [2] = "AES",
    [3] = "DVB-CSA",
}

-- modulation mode
local qam_mode = {
    [1] = "QAM 64",
    [2] = "QAM 256",
    [3] = "QAM 1024",
}

local service_status = {
    [1] = "Operational",
    [2] = "Shutting Down",
    [3] = "Stand by",
}

local transfer_proto_cap = {
    [1]    = "FTP",
    [10]   = "NFS",
    [100]  = "CIFS",
    [1000] = "PGM"
}

-- attribute codes
local RESERVED_TYPE_CODE    = 0
local WITHDRAWN_ROUTES      = 1
local REACHABLE_ROUTES      = 2
local NEXT_HOP_SERVER       = 3
local QAM_NAMES             = 232
local CAS_CAPABLITY         = 233
local TOTAL_BANDWIDTH       = 234
local AVAILBAND_WIDTH       = 235
local COST                  = 236
local EDGE_INPUT            = 237
local QAM_PARAMETER         = 238
local UDP_MAP               = 239
local VOLUME                = 240
local SERVICE_STATUS        = 241
local MPEG_FLOWS            = 242
local NEXT_HOP_SERV_ALTER   = 243
local OUTPUT_PORT           = 244
local OUTPUT_ADDRESS        = 245
local PROTOCOL_CAPABILITIES = 246

local attr_codes = {
    [RESERVED_TYPE_CODE]    = "Reserved Code",
    [WITHDRAWN_ROUTES]      = "Withdrawn Route",
    [REACHABLE_ROUTES]      = "Reachable Route",
    [NEXT_HOP_SERVER]       = "Next Hop Server",
    [QAM_NAMES]             = "Qam Names",
    [CAS_CAPABLITY]         = "CAS Capability",
    [TOTAL_BANDWIDTH]       = "Total Bandwidth",
    [AVAILBAND_WIDTH]       = "Available Bandwidth",
    [COST]                  = "Cost",
    [EDGE_INPUT]            = "Edge Input",
    [QAM_PARAMETER]         = "Qam Parameters",
    [UDP_MAP]               = "UDP Map",
    [VOLUME]                = "Volume",
    [SERVICE_STATUS]        = "Service Status",
    [MPEG_FLOWS]            = "MPEG Flows",
    [NEXT_HOP_SERV_ALTER]   = "Next Hop Server Alter",
    [OUTPUT_PORT]           = "Output Port",
    [OUTPUT_ADDRESS]        = "Output Address",
    [PROTOCOL_CAPABILITIES] = "Protocol Capability",
}

-- notification message
local err_code = {
    [1] = "Message Header Error",
    [2] = "OPEN Message Error",
    [3] = "UPDATE Message Error",
    [4] = "Hold Time Expired",
    [5] = "Finite State Machine Error",
    [6] = "Cease",
}

-- sub error code for the message
local sub_err_header = {
    [1] = "Bad Message Length",
    [2] = "Bad Message Type",
}

local sub_err_open = {
    [1] = "Unsupported Version Number",
    [2] = "Bad Peer Address Domain",
    [3] = "Bad VREP Identifier",
    [4] = "Unsupported Operational Parameters",
    [5] = "Unacceptable Hold Time",
    [6] = "Unsupported Capability",
    [7] = "Capability Mismatch",
}

local sub_err_update = {
    [1] = "Malframed Attribute List",
    [2] = "Unrecognized Well-Known Attribute",
    [3] = "Missing Well-Known Mandatory Attribute",
    [4] = "Attribute Flags Error",
    [5] = "Attribute Length Error",
    [6] = "Invalid Attribute",
}

-- vrep message header type
local pf_length = ProtoField.uint16("vrep.length", "Message Length")
local pf_type = ProtoField.uint8("vrep.type", "Message Type", base.DEC, vrep_type)
local pf_open = ProtoField.bytes("vrep.open", "Open Method")
local pf_update = ProtoField.bytes("vrep.update", "Update Method")
local pf_notify = ProtoField.bytes("vrep.notify", "Notification Method")
local pf_keep = ProtoField.bytes("vrep.keep", "Keepalive Method")

-- Protocol fields for OPEN method
local pf_version = ProtoField.uint8("vrep.open.version", "Version")
local pf_reserved1 = ProtoField.uint8("vrep.open.reserved1", "reserved")
local pf_hold_time = ProtoField.uint16("vrep.open.hold_time", "Hold Time")
local pf_reserved2 = ProtoField.uint32("vrep.open.reserved2", "reserved")
local pf_identifier = ProtoField.uint32("vrep.open.identifier", "VREP Identifier")
local pf_open_param_len = ProtoField.uint16("vrep.open.len", "Parameters Length")
local pf_open_parameter = ProtoField.bytes("vrep.open.param", "Optional Parameters")
-- Protocol fields for open parameter
local pf_open_attr_type = ProtoField.uint16("vrep.open.param.type", "Open Param Type", base.DEC, open_param_type)
local pf_open_attr_len = ProtoField.uint16("vrep.open.param.len", "Length")
local pf_open_attr_var = ProtoField.bytes("vrep.open.param.var", "Value")
local pf_open_attr_cap = ProtoField.bytes("vrep.open.param.cap", "Capability Info")
local pf_open_attr_zone = ProtoField.string("vrep.open.param.zone", "Streaming Zone")
local pf_open_attr_name = ProtoField.string("vrep.open.param.zone", "Component Name")
local pf_open_attr_vendor = ProtoField.string("vrep.open.param.zone", "Vendor Specific String")

-- capability info
local pf_cap_code = ProtoField.uint16("vrep.open.param.cap.code", "Capability Info", base.DEC, cap_code)
local pf_cap_len = ProtoField.uint16("vrep.open.param.cap.len", "Capability Length")
local pf_cap_var = ProtoField.uint16("vrep.open.param.cap.var", "Capability Value")
-- route types
local pf_addr_family = ProtoField.uint16("vrep.open.param.cap.addr_family", "Address Family", base.DEC, supported_route)
local pf_app_proto = ProtoField.uint16("vrep.open.param.cap.app_proto", "Application Protocol", base.DEC, application_protocol)
-- send receive ability
local pf_send_recv_mode = ProtoField.uint32("vrep.open.param.cap.send_recv", "Send Receive Mode", base.DEC, rend_recv_ability)

-- UPDATE message fields
local pf_upd_flag = ProtoField.uint8("vrep.update.flags", "Attribute Flags", base.DEC, attr_flags)
local pf_upd_code = ProtoField.uint8("vrep.update.codes", "Attribute Code", base.DEC, attr_codes)
local pf_upd_leng = ProtoField.uint16("vrep.update.leng", "Attribute Length")
-- generic route format
local pf_upd_attr_family = ProtoField.uint16("vrep.update.route.addr_family", "Address Family")
local pf_upd_attr_protocol = ProtoField.uint16("vrep.update.route.app_proto", "Application Protocol")
local pf_upd_attr_length = ProtoField.uint16("vrep.update.route.length", "Length")
local pf_upd_attr_address = ProtoField.string("vrep.update.route.address", "Address")
-- next hop server format
local pf_upd_attr_nhs_reserved  = ProtoField.uint32("vrep.update.nhs.reserved", "reserved")
local pf_upd_attr_nhs_addr_len  = ProtoField.uint16("vrep.update.nhs.address_len", "Component Address Length")
local pf_upd_attr_nhs_addr  = ProtoField.string("vrep.update.nhs.address", "Component Address")
local pf_upd_attr_nhs_streaming_zone_len  = ProtoField.uint16("vrep.update.nhs.streaming_zone_len", "Streaming Zone Length")
local pf_upd_attr_nhs_streaming_zone  = ProtoField.string("vrep.update.nhs.streaming_zone_len", "Streaming Zone")
-- qam names format
local pf_upd_attr_qn_len = ProtoField.uint16("vrep.update.qn.qam_name_len", "QAM Name Length")
local pf_upd_attr_qn = ProtoField.string("vrep.update.qn.qam_name", "QAM Name")
-- cas capability format
local pf_upd_attr_cas_type = ProtoField.uint8("vrep.update.cas.type", "CAS Type", base.DEC, cas_type)
local pf_upd_attr_cas_scheme = ProtoField.uint8("vrep.update.cas.enc_scheme", "Encryption Scheme", base.DEC, enc_scheme)
local pf_upd_attr_cas_key_len = ProtoField.uint16("vrep.update.cas.key_len", "Key Length")
local pf_upd_attr_cas_identifier = ProtoField.uint16("vrep.update.cas.cas_id", "CAS Identifier")
-- total bandwidth format
local pf_upd_attr_total_bandwidth = ProtoField.uint32("vrep.update.total_bandwidth", "Total Bandwidth(KBps)")
-- available bandwith format
local pf_upd_attr_available_bandwidth = ProtoField.uint32("vrep.update.available_bandwidth", "Available Bandwidth(KBps)")
-- cost
local pf_upd_attr_cost = ProtoField.uint8("vrep.update.cost", "Cost")
-- edge input format
local pf_upd_attr_edge_input_mask = ProtoField.uint32("vrep.update.edge_input.net_mask", "Subnet Mask")
local pf_upd_attr_edge_input_leng = ProtoField.uint16("vrep.update.edge_input.host_leng", "Host Name Length")
local pf_upd_attr_edge_input_host = ProtoField.string("vrep.update.edge_input.host", "Host Name")
local pf_upd_attr_edge_input_port = ProtoField.uint32("vrep.update.edge_input.port_id", "Port ID")
local pf_upd_attr_edge_input_max_bandwidth =  ProtoField.uint32("vrep.update.edge_input.max_bandwidth", "Max Group Bandwidth")
local pf_upd_attr_edge_input_group_name_len = ProtoField.uint16("vrep.update.edge_input.group_name_len", "Group Name Length")
local pf_upd_attr_edge_input_group_name = ProtoField.string("vrep.update.edge_input.group_name", "Group Name")
-- qam parameters format
local pf_upd_attr_qam_param_freq = ProtoField.uint32("vrep.update.qam_params.frequency", "Frequency(KHz)")
local pf_upd_attr_qam_param_mode = ProtoField.uint8("vrep.update.qam_params.mod", "Modulation Mode", base.DEC, qam_mode)
local pf_upd_attr_qam_param_inte = ProtoField.uint8("vrep.update.qam_params.interleaver", "FEC Interleaver")
local pf_upd_attr_qam_param_tsid = ProtoField.uint16("vrep.update.qam_params.tsid", "TS ID")
local pf_upd_attr_qam_param_annx = ProtoField.uint8("vrep.update.qam_params.annex", "QAM ITU-T Annex")
local pf_upd_attr_qam_param_chan = ProtoField.uint8("vrep.update.qam_params.channel_width", "Channel Width(MHz)")
-- udp map
local pf_upd_attr_udp_map_static = ProtoField.uint32("vrep.update.udp_map.static_num", "Static Map Number")
local pf_upd_attr_udp_map_port = ProtoField.uint16("vrep.update.udp_map.port", "Port")
local pf_upd_attr_udp_map_program = ProtoField.uint16("vrep.update.udp_map.program", "Program")
local pf_upd_attr_udp_map_dynamic = ProtoField.uint32("vrep.update.udp_map.dynamic_num", "Dynamic Map Number")
local pf_upd_attr_udp_map_port_start = ProtoField.uint16("vrep.update.udp_map.dynamic_num", "Starting Port")
local pf_upd_attr_udp_map_program_start = ProtoField.uint16("vrep.update.udp_map.dynamic_num", "Starting Program")
local pf_upd_attr_udp_map_count = ProtoField.uint32("vrep.update.udp_map.dynamic_num", "Count")
-- volume format
-- service status format
local pf_upd_attr_service_status = ProtoField.uint32("vrep.update.service_status", "Service Status", base.DEC, service_status)
-- MPEG flows format
local pf_upd_attr_mpeg_flows = ProtoField.uint32("vrep.update.mpeg_flows", "MPEG Flows")
-- output port format
local pf_upd_attr_port_id = ProtoField.uint32("vrep.update.output_port_id", "Output Port ID")
-- output address format
local pf_upd_attr_output_addr_len = ProtoField.uint16("vrep.update.output_address.len", "Output Address Length")
local pf_upd_attr_output_addr = ProtoField.string("vrep.update.output_address.addr", "Output Address")
-- transfer protocol capabilities
local pf_upd_attr_transfer_proto_cap = ProtoField.uint8("vrep.update.transfer_proto_cap", "Transfer Protocol Capabilities", base.DEC, transfer_proto_cap)
-- notification message format
local pf_ntf_err = ProtoField.uint8("vrep.notification.err", "Error Code", base.DEC, err_code)
local pf_ntf_sub_err_header = ProtoField.uint8("vrep.notification.sub_err_header","Header Sub Error Code",base.DEC, sub_err_header)
local pf_ntf_sub_err_open = ProtoField.uint8("vrep.notification.sub_err_open","Open Sub Error Code",base.DEC, sub_err_open)
local pf_ntf_sub_err_update = ProtoField.uint8("vrep.notification.sub_err_update","UPDATE Sub Error Code",base.DEC, sub_err_update)
local pf_ntf_data = ProtoField.bytes("vrep.notification.data", "Code")

-- register the ProtoField
vrep.fields = {
    pf_length, -- header
    pf_type,
    pf_open,
    pf_update,
    pf_notify,
    pf_keep,
    pf_version, -- update message
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
    pf_open_attr_zone,
    pf_open_attr_name,
    pf_open_attr_vendor,
    pf_cap_code,
    pf_cap_len,
    pf_cap_var,
    pf_addr_family,
    pf_app_proto,
    pf_send_recv_mode,
    pf_upd_flag, -- update message
    pf_upd_code,
    pf_upd_leng,
    pf_upd_attr_family,
    pf_upd_attr_protocol,
    pf_upd_attr_length,
    pf_upd_attr_address,
    pf_upd_attr_nhs_reserved,
    pf_upd_attr_nhs_addr_len,
    pf_upd_attr_nhs_addr,
    pf_upd_attr_nhs_streaming_zone_len,
    pf_upd_attr_nhs_streaming_zone,
    pf_upd_attr_qn_len,
    pf_upd_attr_qn,
    pf_upd_attr_cas_type,
    pf_upd_attr_cas_scheme,
    pf_upd_attr_cas_key_len,
    pf_upd_attr_cas_identifier,
    pf_upd_attr_total_bandwidth,
    pf_upd_attr_available_bandwidth,
    pf_upd_attr_cost,
    pf_upd_attr_edge_input_mask,
    pf_upd_attr_edge_input_leng,
    pf_upd_attr_edge_input_host,
    pf_upd_attr_edge_input_port,
    pf_upd_attr_edge_input_max_bandwidth,
    pf_upd_attr_edge_input_group_name_len,
    pf_upd_attr_edge_input_group_name,
    pf_upd_attr_qam_param_freq,
    pf_upd_attr_qam_param_mode,
    pf_upd_attr_qam_param_inte,
    pf_upd_attr_qam_param_tsid,
    pf_upd_attr_qam_param_annx,
    pf_upd_attr_qam_param_chan,
    pf_upd_attr_udp_map_static,
    pf_upd_attr_udp_map_port,
    pf_upd_attr_udp_map_program,
    pf_upd_attr_udp_map_dynamic,
    pf_upd_attr_udp_map_port_start,
    pf_upd_attr_udp_map_program_start,
    pf_upd_attr_udp_map_count,
    pf_upd_attr_service_status,
    pf_upd_attr_mpeg_flows,
    pf_upd_attr_port_id,
    pf_upd_attr_output_addr_len,
    pf_upd_attr_output_addr,
    pf_upd_attr_transfer_proto_cap,
    pf_ntf_err,
    pf_ntf_sub_err_header,
    pf_ntf_sub_err_open,
    pf_ntf_sub_err_update,
    pf_ntf_data,
}

dprint2("VREP ProtoField registered")

-- open method dissector
-- implementation of above function
-- the return value of all these functions are the number of bytes dissected
local function h_cap(tvbuf, pos, len, root)
    local attr_tree = root:add("Capability Info")
    local start = pos
    while start + len > pos do
        local pos_cpy = pos
        local code_range = tvbuf:range(pos, 2)
        local len_range = tvbuf:range(pos + 2, 2)
        -- attr_tree:add(pf_cap_code, code_range)
        -- attr_tree:add(pf_cap_len, len_range)
        local cap_code = code_range:uint()
        local cap_len = len_range:uint()
        pos = pos + 4
        if cap_code == 1 then
            local subtree = attr_tree:add("Route Type Supported")
            subtree:add(pf_addr_family, tvbuf:range(pos, 2))
            subtree:add(pf_app_proto, tvbuf:range(pos + 2, 2))
        elseif cap_code == 2 then
            -- local subtree = attribute:add("Send Receive Mode")
            attr_tree:add(pf_send_recv_mode, tvbuf(pos, 4))
        end
        pos = pos + cap_len
    end
    return len
end

local function h_zone(tvbuf, pos, len, root)
    root:add(pf_open_attr_zone, tvbuf:range(pos, len))
    return len
end

local function h_name(tvbuf, pos, len, root)
    root:add(pf_open_attr_name, tvbuf:range(pos, len))
    return len
end

local function h_vendor(tvbuf, pos, len, root)
    root:add(pf_open_attr_vendor, tvbuf:range(pos, len))
    return len
end

-- update message dissectors
local function u_reserved_type_code(tvbuf, pos, len, root)
    -- just do nothing, it's an error if this fucntion was called
end

function gen_route(tvbuf, pos, len, root)
    local pos_cpy = pos
    while len > pos - pos_cpy do
        root:add(pf_upd_attr_family, tvbuf:range(pos, 2))
        root:add(pf_upd_attr_protocol, tvbuf:range(pos + 2, 2))
        local range = tvbuf:range(pos + 4, 2)
        root:add(pf_upd_attr_length, range)
        local address_len = range:uint()
        pos = pos + 6
        root:add(pf_upd_attr_address, tvbuf:range(pos, address_len))
        pos = pos + address_len
    end
    return len
end

local function u_withdrawn_routes(tvbuf, pos, len, root)
    local subtree = root:add("Withdrawn Route")
    local x = gen_route(tvbuf, pos, len, subtree)
    return x
end

local function u_reachable_routes(tvbuf, pos, len, root)
    local subtree = root:add("Reachable Route")
    local x = gen_route(tvbuf, pos, len, subtree)
    return x
end

local function u_next_hop_server(tvbuf, pos, len, root)
    local subtree = root:add("Next Hop Server")
    local pos_cpy = pos
    if(len < 4) then
        return 4-len;
    end
    subtree:add(pf_upd_attr_nhs_reserved, tvbuf:range(pos, 4))
    pos = pos + 4

    if len < 2 + pos - pos_cpy then
        return 2 + pos - pos_cpy - len
    end
    local range = tvbuf:range(pos, 2)
    subtree:add(pf_upd_attr_nhs_addr_len, range)
    local sub_len = range:uint()
    pos = pos + 2

    if len < pos - pos_cpy + sub_len then
        return pos - pos_cpy + sub_len -len
    end
    subtree:add(pf_upd_attr_nhs_addr, tvbuf:range(pos, sub_len))
    pos = pos + sub_len

    if len < pos - pos_cpy + 2 then
        return pos - pos_cpy + 2 -len
    end
    range = tvbuf:range(pos, 2)
    subtree:add(pf_upd_attr_nhs_streaming_zone_len, range)
    sub_len = range:uint()
    pos = pos + 2

    if len < pos - pos_cpy + sub_len then
        return pos - pos_cpy + sub_len-len
    end
    subtree:add(pf_upd_attr_nhs_streaming_zone, tvbuf:range(pos, sub_len))
    return len
end

local function u_qam_names(tvbuf, pos, len, root)
    local pos_cpy = pos
    local subtree = root:add("QAM Names")
    while len > pos - pos_cpy do
        local range = tvbuf:range(pos, 2)
        local len = range:uint()
        subtree:add(pf_upd_attr_qn_len,range)
        subtree:add(pf_upd_attr_qn, tvbuf:range(pos+2, len))
        pos = pos + 2 + len
    end
    return len
end

local function u_cas_capablity(tvbuf, pos, len, root)
    if len < 6 then
        return 6 - len
    end
    local subtree = root:add("CAS Capability")
    subtree:add(pf_upd_attr_cas_type, tvbuf:range(pos, 1))
    subtree:add(pf_upd_attr_cas_scheme, tvbuf:range(pos+1, 1))
    subtree:add(pf_upd_attr_cas_key_len, tvbuf:range(pos+2, 2))
    subtree:add(pf_upd_attr_cas_identifier, tvbuf:range(pos+4, 2))
    return len
end

local function u_total_bandwidth(tvbuf, pos, len, root)
    if len < 4 then
        return len - 4
    end
    root:add(pf_upd_attr_total_bandwidth, tvbuf:range(pos, 4))
    return len
end

local function u_availband_width(tvbuf, pos, len, root)
    if len < 4 then
        return len - 4
    end
    root:add(pf_upd_attr_available_bandwidth, tvbuf:range(pos, 4))
    return len
end

local function u_cost(tvbuf, pos, len, root)
    if len < 1 then
        return -1
    end
    root:add(pf_upd_attr_cost, tvbuf:range(pos, 1))
    return len
end

local function u_edge_input(tvbuf, pos, len, root)
    local subtree = root:add("Edge Input")
    local pos_cpy = pos
    while len > pos - pos_cpy do
        subtree:add(pf_upd_attr_edge_input_mask, tvbuf:range(pos, 4))
        pos = pos + 4
        local range = tvbuf:range(pos, 2)
        subtree:add(pf_upd_attr_edge_input_leng, range)
        local sub_len = range:uint()
        pos = pos + 2

        subtree:add(pf_upd_attr_edge_input_host, tvbuf:range(pos, sub_len))
        pos = pos + sub_len

        subtree:add(pf_upd_attr_edge_input_port, tvbuf:range(pos, 4))
        pos = pos + 4

        subtree:add(pf_upd_attr_edge_input_max_bandwidth, tvbuf:range(pos, 4))
        pos = pos + 4

        range = tvbuf:range(pos, 2)
        subtree:add(pf_upd_attr_edge_input_group_name_len, range)
        sub_len = range:uint()
        pos = pos + 2

        subtree:add(pf_upd_attr_edge_input_group_name, tvbuf:range(pos, sub_len))
        pos = pos + sub_len
    end
    return len
end

local function u_qam_parameter(tvbuf, pos, len, root)
    if len < 12 then
        return 12 -len
    end
    local subtree = root:add("QAM Parameters")
    subtree:add(pf_upd_attr_qam_param_freq, tvbuf:range(pos, 4))
    subtree:add(pf_upd_attr_qam_param_mode, tvbuf:range(pos+4, 1))
    subtree:add(pf_upd_attr_qam_param_inte, tvbuf:range(pos+5, 1))
    subtree:add(pf_upd_attr_qam_param_tsid, tvbuf:range(pos+6, 2))
    subtree:add(pf_upd_attr_qam_param_annx, tvbuf:range(pos+8, 1))
    subtree:add(pf_upd_attr_qam_param_chan, tvbuf:range(pos+9, 1))
    return len
end

local function u_udp_map(tvbuf, pos, len, root)
    local pos_cpy = pos
    local subtree  = root:add("UDP Maps")
    local range = tvbuf:range(pos, 4)
    local count = range:uint()
    subtree:add(pf_upd_attr_udp_map_static, range)
    pos = pos + 4
    while count > 0 and len > pos - pos_cpy do
        subtree:add(pf_upd_attr_udp_map_port, tvbuf:range(pos, 2))
        subtree:add(pf_upd_attr_udp_map_program, tvbuf:range(pos+2, 2))
        pos = pos+ 4
        count = count -1
    end

    if len > pos - pos_cpy then
        range = tvbuf:range(pos, 4)
        count = range:uint()
        subtree:add(pf_upd_attr_udp_map_dynamic, range)
        pos = pos + 4
        while len > pos - pos_cpy and count > 0 do
            subtree:add(pf_upd_attr_udp_map_port_start, tvbuf:range(pos, 2))
            subtree:add(pf_upd_attr_udp_map_program_start, tvbuf:range(pos+2, 2))
            subtree:add(pf_upd_attr_udp_map_count, tvbuf:range(pos+4, 4))
            pos = pos + 8
            count = count - 1
        end
    end
    return len
end

local function u_volume(tvbuf, pos, len, root)
    return len
end

local function u_service_status(tvbuf, pos, len, root)
    if len < 4 then
        return 4 - len
    end
    root:add(pf_upd_attr_service_status, tvbuf:range(pos, 4))
    return len
end

local function u_mpeg_flows(tvbuf, pos, len, root)
    if len < 4 then
        return 4 - len
    end
    root:add(pf_upd_attr_mpeg_flows, tvbuf:range(pos, 4))
    return len
end

local function u_next_hop_serv_alter(tvbuf, pos, len, root)
    return len
end

local function u_output_port(tvbuf, pos, len, root)
    if len < 4 then
        return 4 - len
    end
    root:add(pf_upd_attr_port_id, tvbuf:range(pos, 4))
    return len
end

local function u_output_address(tvbuf, pos, len, root)
    if len < 2 then
        return 2 - len
    end

    local range = tvbuf:range(pos, 2)
    local sub_len = range:uint()

    if len < 2 + sub_len then
        return 2 + sub_len -len
    end
    root:add(pf_upd_attr_output_addr, tvbuf:range(pos+2, sub_len))
    return len
end

local function u_protocol_capabilities(tvbuf, pos, len, root)
    if len < 1 then
        return -1
    end
    root:add(pf_upd_attr_transfer_proto_cap, tvbuf:range(pos, 1))
    return len
end


-- add above to open method dissector table
local open_dissector = {
    [1] = h_cap,
    [2] = h_zone,
    [3] = h_name,
    [4] = h_vendor,
}

local update_dissector = {
    [RESERVED_TYPE_CODE]    = u_reserved_type_code,
    [WITHDRAWN_ROUTES]      = u_withdrawn_routes,
    [REACHABLE_ROUTES]      = u_reachable_routes,
    [NEXT_HOP_SERVER]       = u_next_hop_server,
    [QAM_NAMES]             = u_qam_names,
    [CAS_CAPABLITY]         = u_cas_capablity,
    [TOTAL_BANDWIDTH]       = u_total_bandwidth,
    [AVAILBAND_WIDTH]       = u_availband_width,
    [COST]                  = u_cost,
    [EDGE_INPUT]            = u_edge_input,
    [QAM_PARAMETER]         = u_qam_parameter,
    [UDP_MAP]               = u_udp_map,
    [VOLUME]                = u_volume,
    [SERVICE_STATUS]        = u_service_status,
    [MPEG_FLOWS]            = u_mpeg_flows,
    [NEXT_HOP_SERV_ALTER]   = u_next_hop_serv_alter,
    [OUTPUT_PORT]           = u_output_port,
    [OUTPUT_ADDRESS]        = u_output_address,
    [PROTOCOL_CAPABILITIES] = u_protocol_capabilities,
}

--------------------------------------------------------------------------------
local function h_open(tvbuf, pos, len, root)
    local pos_cpy = pos
    local subtree = root:add("Open Method")
    subtree:add(pf_version, tvbuf:range(pos, 1))
    subtree:add(pf_reserved1, tvbuf:range(pos + 1, 1))
    subtree:add(pf_hold_time, tvbuf:range(pos + 2, 2))
    subtree:add(pf_reserved2, tvbuf:range(pos + 4, 4))
    subtree:add(pf_identifier, tvbuf:range(pos + 8, 4))
    -- subtree:add(pf_open_param_len, tvbuf:range(pos + 12, 2))
    local param_len = tvbuf:range(pos + 12, 2):uint()
    pos = pos + 14
    len = len - 14
    if param_len > 0 then
        local param_tree = subtree:add("Optional Parameters")
        while param_len > 0 do
            local type_range = tvbuf:range(pos, 2)
            local len_range = tvbuf:range(pos + 2, 2)
            local para_type = type_range:uint()
            local para_len = len_range:uint()
            -- param_tree:add(pf_open_attr_type, type_range)
            -- param_tree:add(pf_open_attr_len, len_range)
            local handler = open_dissector[para_type]
            local dissected_len = 0
            if handler ~= nil then
                dissected_len = handler(tvbuf, pos + 4, para_len, param_tree)
            else
                print("unkown open method parameter type code:" .. tostring(para_type))
                return pos - pos_cpy
            end
            pos = pos + 4 + dissected_len
            param_len = param_len - 4 - dissected_len
        end
    end
end

local function h_update(tvbuf, pos, len, root)
    local pos_cpy = pos
    -- note that vrep update message can be empty
    if len > 0 then
        local subtree = root:add("Update Info")
        while len > pos - pos_cpy do
            subtree:add(pf_upd_flag, tvbuf:range(pos, 1))
            local range = tvbuf:range(pos + 1, 1)
            local opcode = range:uint()
            subtree:add(pf_upd_code, range)
            range = tvbuf:range(pos+2, 2)
            local len = range:uint()
            pos = pos + 4
            subtree:add(pf_upd_leng, range)
            if len > 0 then
                local h = update_dissector[opcode]
                if h ~= nil then
                    local ret = h(tvbuf, pos, len, subtree)
                    pos = pos + ret
                end
            end
        end
    end
end

local sub_err_handler = {
    [1] = pf_ntf_sub_err_header,
    [2] = pf_ntf_sub_err_open,
    [3] = pf_ntf_sub_err_update,
}

local function h_notification(tvbuf, pos, len, root)
    if len < 2 then
        return -2
    end
    local range = tvbuf:range(pos, 1)
    local code = range:uint()
    root:add(pf_ntf_err, range)

    h = sub_err_handler[code]
    if h ~= nil then
        root:add(h, tvbuf:range(pos+1,1))
    end

    if len > 2 then
        root:add(pf_ntf_data, tvbuf:range(pos+2, len - 2))
    end
end

local function h_keepalive(tvbuf, pos, len, root)
    return len
end

local fun_table = {
    [OPEN]         = h_open,
    [UPDATE]       = h_update,
    [NOTIFICATION] = h_notification,
    [KEEPALIVE]    = h_keepalive
}
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
    local msgtype_val = msgtype_tvbr:uint()
    tree:add(pf_type, msgtype_tvbr)
    local handler = fun_table[msgtype_val]
    if handler ~= nil then
        handler(tvbuf, offset + 3, length_val - 3, tree)
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
checkVREPLength = function(tvbuf, offset)

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
            return - DESEGMENT_ONE_MORE_SEGMENT
        end

        -- if we got here, then we know we have enough bytes in the Tvb buffer
        -- to at least figure out the full length of this VREP messsage (the length
        -- is the 16-bit integer in third and fourth bytes)
        -- get the TvbRange of bytes 3+4
        local length_tvbr = tvbuf:range(offset, 2)

        -- get the length as an unsigned integer, in network-order (big endian)
        local length_val = length_tvbr:uint()

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

    emptyBytes = function(num)
        return string.rep("\000", num)
    end

    createSllTvb = function(tvbuf, begin, length)
        dprint2("VREP createSllTvb function called, using 1.12+ method")
        -- the SLL header and Netlink message
        local sllmsg =
            {
                emptyBytes(2), -- Unused 2B
                ARPHRD_NETLINK, -- netlink type
                emptyBytes(10), -- Unused 10B
                WS_NETLINK_ROUTE, -- Route type
                tvbuf:raw(begin, length)-- the Netlink message
            }
        local payload = table.concat(sllmsg)

        return ByteArray.new(payload, true):tvb("Netlink Message")
    end

else
    -- prior to 1.12, the only way to create a ByteArray was from hex-ascii
    -- so we do things in hex-ascii
    ARPHRD_NETLINK = "0338"
    WS_NETLINK_ROUTE = "0000"

    emptyBytes = function(num)
        return string.rep("00", num)
    end

    createSllTvb = function(tvbuf, begin, length)
        dprint2("VREP createSllTvb function called, using pre-1.12 method")

        -- first get a TvbRange from the Tvb, and the TvbRange's ByteArray...
        local nl_bytearray = tvbuf(begin, length):bytes()

        -- then create a hex-ascii string of the SLL header portion
        local sllmsg =
            {
                emptyBytes(2), -- Unused 2B
                ARPHRD_NETLINK, -- netlink type
                emptyBytes(10), -- Unused 10B
                WS_NETLINK_ROUTE -- Route type
            }
        local hexSLL = table.concat(sllmsg)

        -- then create a ByteArray from that hex-string
        local sll_bytearray = ByteArray.new(hexSLL)

        -- then concatenate the two ByteArrays
        local full_bytearray = sll_bytearray .. nl_bytearray

        -- create the new Tvb from the full ByteArray
        -- and because this is pre-1.12, we need to store them longer to
        -- work around bug 10888
        tvbs[#tvbs + 1] = full_bytearray:tvb()

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
    {1, "Disabled", debug_level.DISABLED},
    {2, "Level 1", debug_level.LEVEL_1},
    {3, "Level 2", debug_level.LEVEL_2},
}

----------------------------------------
-- register our preferences
vrep.prefs.enabled = Pref.bool("Dissector enabled", default_settings.enabled,
    "Whether the VREP dissector is enabled or not")

vrep.prefs.subdissect = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
    "Whether the VREP packet's content" ..
    " should be dissected or not")

vrep.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
    "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function vrep.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect = vrep.prefs.subdissect

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
