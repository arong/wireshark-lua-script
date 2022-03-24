## 如何使用
1. 下载附件, 如果下面的链接全部失效, 则建议从[脚本源码](#src)复制另存.
    - ipanel CVS: `cvs2033:/tools/Wireshark插件/mpeg_packets_dump.lua`
    - [Github][github_src]
    - [Wireshark][ws_src]
2. 将脚本保存到Wireshark的目录. 比如`c:\Program Files\Wireshark`, 文件名为 `mpeg_packets_dump.lua`
3. 编辑Wireshark目录中的`init.lua`, 在文件末尾添加一行`dofile("mpeg_packets_dump.lua")`
4. 重启Wireshark使插件生效
5. 抓取一些包含MPEG TS的数据流(或者打开一个已有的包)
6. 停止录流, 选择 `Tools -> Dump MPEG TS Packets`
7. 输入将要保存的文件的文件名, 比如`dump.ts`
8. 为了只输出一路流, 可以输入过滤条件, 也可以留空
9. 点击`OK`, 在本次捕捉中抓到的所有符合过滤条件的MPEG包会被输出到你的输出文件中(一般存放在与网络包相同的文件夹).

## about this
该脚本基于Wireshark官网的一个脚本改造. 主要改动是使用内置函数提高了处理速度. 目前测试过的最大文件大小为2.5G.

### 注意GPL
Wireshark依照GPL许可证发布, 所以任何基于Wireshark的衍生内容必须以GPL许可证发布, 也就是本脚本的发行许可也是GPL.


## <a name="src">脚本源码</a> 
如果本文提供的下载链接失效, 那么可以手动拷贝如下脚本另存为`mpeg_packets_dump.lua`
```lua
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
```

[ws_page]: https://wiki.wireshark.org/mpeg_dump.lua
[ws_src]:https://wiki.wireshark.org/mpeg_dump.lua?action=AttachFile&do=view&target=mpeg_packets_dump.lua
[github_src]:https://github.com/arong/wireshark-lua-script