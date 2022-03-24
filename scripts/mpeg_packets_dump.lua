-- Wireshark extension to dump MPEG2 transport stream packets
--
-- To use this script:
-- 1. Save it in the Wireshark home directory e.g. c:\Program Files\Wireshark
-- 2. Edit init.lua in the Wireshark home directory and add the following line
--    dofile("mpeg_packets_dump.lua")
-- 3. Restart Wireshark to add the extension
-- 4. Capture some traffic which includes some MPEG transport packets, for
--    example, it has been tested with MPEG transmitted via UDP multicast.
-- 5. Stop the capture, and select Tools -> Dump MPEG TS Packets
-- 6. Enter the file where the mpeg stream should be saved.
-- 7. In order to select only one of many streams, enter a wireshark filter
--    expression, or you can leave the filter blank.
-- 8. Press okay. Any MPEG packets in the current capture which were detected
--    by the MPEG dissector and that match your filter will be dumped to
--    your output file.
--
-- Tested with Wireshark 1.4.3
-- ryan.gorsuch_at_echostar_com
-- 2011-04-01
-- Modified and tested with Wireshark 1.11.3
-- hadrielk_at_yahoo_com
-- 2014-02-17
-- only works in wireshark, not tshark
-- 
-- Modified by Aronic to replace some util function to build-in api.
-- 2017-11-02
-- xurd at ipanel dot cn

if not GUI_ENABLED then
    print("mpeg_packets_dump.lua only works in Wireshark")
    return
end

-- declare some field extractors
local mpeg_pid = Field.new("mp2t.pid")
local mpeg_pkt = Field.new("mp2t")

-- do a payload dump when prompted by the user
local function init_payload_dump(file, filter)
    local packet_count = 0
    local tap = Listener.new(nil, filter)
    local myfile = assert(io.open(file, "w+b"))
    
    -- this function is going to be called once each time our filter matches
    function tap.packet(pinfo, tvb)
        if (mpeg_pid()) then
            packet_count = packet_count + 1
            
            -- there can be multiple mp2t packets in a given frame, so get them all into a table
            local contents = {mpeg_pkt()}
            
            for i, finfo in ipairs(contents) do
                local tvbrange = finfo.range
                local subtvb = tvbrange:tvb()
                myfile:write(subtvb:raw())
                -- myfile:flush()
            end
        end
    end
    
    -- re-inspect all the packets that are in the current capture, thereby
    -- triggering the above tap.packet function
    retap_packets()
    
    -- cleanup
	myfile:flush()
    myfile:close()
    tap:remove()
    debug("Dumped mpeg packets: " .. packet_count)
end

-- show this dialog when the user select "Dump" from the Tools menu
local function begin_dialog_menu()
    new_dialog("Dump MPEG TS Packets", init_payload_dump, "Output file", "Packet filter (optional)\n\nExamples:\nip.dst == 225.1.1.4\nmp2t\nmp2t.pid == 0x300")
end

register_menu("Dump MPEG TS Packets", begin_dialog_menu, MENU_TOOLS_UNSORTED)
