# Window title
window-title = swyh-rs UPNP/DLNA 流媒体 V{ $version }

# Configuration panel
config-options = 配置选项
choose-color-theme = 选择颜色主题
color-theme-label = 颜色主题：{ $name }
widget-style-label = 控件样式：{ $style }
language-label = 语言：{ $lang }
warn-language-changed = 语言已更改为 { $lang }，需要重启！！
warn-widget-style-changed = 控件样式已更改为 { $style }，需要重启！！
active-network = 活动网络：{ $addr }
new-network-label = 新网络：{ $name }
audio-source-label = 音频源：{ $name }
new-audio-source-label = 新音频源：{ $name }

# Checkboxes and controls
chk-autoresume = 自动恢复播放
chk-autoreconnect = 自动重连
chk-enable-slimproto = 启用 SlimProto
ssdp-interval-label = SSDP 间隔（分钟）
btn-ssdp-discover = 立即运行 SSDP 发现
log-level-label = 日志级别：{ $level }
fmt-label = 格式：{ $format }
chk-24bit = 24 位
sample-rate-label = 采样率（Hz）：
sr-system-default = 系统默认（{ $rate } Hz）
http-port-label = HTTP 端口：
chk-use-dither = 16位 TPDF 抖动
chk-inject-silence = 注入静音
strmsize-label = 流大小：{ $size }
buffer-label = 初始缓冲区（毫秒）：
chk-rms-monitor = RMS 监视器
btn-apply-config = 点击应用配置更改
upnp-devices = 网络 { $addr } 上的 UPNP 渲染设备

# 标签页标题
tab-audio = 音频
tab-network = 网络
tab-app = 应用
tab-status = 状态
tab-netease = 网易云

# 网易云音乐
netease-cookie-label = Cookie（可选）：
netease-quality-label = 音质：
netease-search-label = 搜索歌曲：
netease-renderer-label = 渲染器：
btn-netease-search = 搜索
btn-netease-load = 载入
btn-netease-refresh = 刷新
btn-netease-play = 播放
btn-netease-playall = 播放全部
btn-netease-next = 下一首
btn-netease-stop = 停止
netease-api-changed = 网易云 API 地址已更改为 { $url }
netease-cookie-changed = 网易云 Cookie 已更新
netease-quality-changed = 网易云音质已更改为 { $quality }
netease-search-result = 搜索「{ $keywords }」找到 { $count } 首歌曲
netease-playlist-loaded = 歌单 { $id } 已载入 { $count } 首歌曲
netease-bad-playlist = 无效的歌单 ID：{ $id }
netease-no-track = 网易云：没有可播放的曲目，请先搜索或载入歌单
netease-no-renderer = 网易云：没有可用的渲染器，请先发现并选择一台设备
netease-user-label = 网易云账户：
netease-logged-in = 已登录：{ $nickname }
netease-logged-out = 未登录
btn-netease-login = 扫码登录
btn-netease-logout = 登出
btn-netease-playlist-refresh = 刷新歌单
netease-playlist-label = 我的歌单：
netease-playlist-empty = 暂无歌单
netease-qr-window-title = 网易云扫码登录
netease-qr-status-init = 正在生成二维码…
netease-qr-status-waiting = 请用网易云 APP 扫码
netease-qr-status-scanned = 已扫码，请在手机上确认登录
netease-qr-status-success = 登录成功
netease-qr-status-expired = 二维码已过期，请点击「刷新二维码」
netease-qr-status-error = 二维码错误：{ $msg }
netease-login-failed = 登录失败：{ $msg }
netease-playlist-count = 已加载 { $count } 个歌单
netease-user-info-failed = 获取用户信息失败：{ $msg }
netease-csrf-missing = NetEase：Cookie 缺少 __csrf — 搜索将返回空 body
netease-empty-body = NetEase：{ $path } 返回 200 OK 但 body 为空 — Cookie 无效或过期

# Status messages
status-setup-audio = 配置音频源
status-injecting-silence = 正在向输出流注入静音
status-starting-ssdp = 正在启动 SSDP 发现
status-ssdp-interval-zero = SSDP 间隔为 0 => 跳过 SSDP 发现
status-starting-slimproto = 正在启动 SlimProto 发现
status-slimproto-disabled = SlimProto 发现已禁用
status-loaded-config = 已加载配置 -c { $id }
status-serving-started = 已在端口 { $port } 上启动服务...
status-playing-to = 正在播放到 { $name }
status-shutting-down = 正在关闭 { $name }
status-dry-run-exit = 演习模式 - 正在退出...
status-new-renderer = 在 { $addr } 发现新渲染器 { $name }

# Format / stream size change notifications
info-format-changed = 当前流媒体格式已更改为 { $format }
info-streamsize-changed = { $format } 的流大小已更改为 { $size }

# Warning messages (restart required)
warn-network-changed = 网络已更改为 { $name }，需要重启！！
warn-audio-changed = 音频源已更改为 { $name }，需要重启！！
warn-ssdp-changed = SSDP 间隔已更改为 { $interval } 分钟，需要重启！！
warn-slimproto-changed = SlimProto 支持已更改，需要重启！！
warn-log-changed = 日志级别已更改为 { $level }，需要重启！！

# Audio capture
audio-capturing-from = 正在从以下设备捕获音频：{ $name }
audio-default-config = 默认音频 { $cfg }
audio-capture-format = 音频捕获采样格式 = { $fmt }
err-capture-format-stream = 捕获 { $fmt } 音频流时出错：{ $error }
err-capture-stream = 捕获音频输入流时出错 { $error }
audio-capture-receiving = 音频捕获现在正在接收采样。

# FLAC encoder
err-flac-already-running = FLAC 编码器已在运行！
err-flac-cant-start = 无法启动 FLAC 编码器
err-flac-start-error = FLAC 编码器启动错误 { $error }
flac-encoder-end = FLAC 编码器线程：结束。
flac-encoder-silence-end = FLAC 编码器线程（注入近静音）：结束。
flac-encoder-exit = FLAC 编码器线程退出。
err-flac-spawn = 无法生成 FLAC 编码器线程：{ $error }。

# Silence injection
err-inject-silence-stream = 注入静音：输出音频流发生错误：{ $error }
err-inject-silence-format = 注入静音：不支持的采样格式：{ $format }
err-inject-silence-play = 无法播放注入静音流。
err-inject-silence-build = 无法构建注入静音流：{ $error }

# SSDP discovery errors
err-ssdp-no-network = SSDP：配置中没有活动网络。
err-ssdp-parse-ip = SSDP：无法解析本地 IP 地址。
err-ssdp-bind = SSDP：无法绑定到套接字。
err-ssdp-broadcast = SSDP：无法将套接字设置为广播模式。
err-ssdp-ttl = SSDP：无法在套接字上设置 DEFAULT_SEARCH_TTL。
err-ssdp-oh-send = SSDP：无法发送 OpenHome 发现消息
err-ssdp-av-send = SSDP：无法发送 AV Transport 发现消息

# Process priority
priority-nice = 现在以 nice 值 -10 运行
priority-above-normal = 现在以 ABOVE_NORMAL_PRIORITY_CLASS 运行
err-priority-windows = 无法将进程优先级设置为 ABOVE_NORMAL，错误 = { $error }
err-priority-linux = 抱歉，您没有提升优先级的权限...

# Error messages
err-no-audio-device = 未找到默认音频设备！
err-no-sound-source = 配置中没有声音源！
err-no-local-address = 无法获取本地网络地址！
err-capture-audio = 无法捕获音频...请检查配置。
err-play-stream = 无法播放音频流。
err-inject-silence = 无法注入静音！！
err-ssdp-spawn = 无法生成 SSDP 发现线程：{ $error }
err-rms-spawn = 无法生成 RMS 监视器线程：{ $error }
err-server-spawn = 无法生成 HTTP 流媒体服务器线程：{ $error }

# Debug build indicator
debug-build-warning = 正在运行调试版本 => 日志级别已设置为 DEBUG！

# CLI: audio source discovery
cli-found-audio-source = 找到音频源：索引 = { $index }，名称 = { $name }
cli-selected-audio-source-idx = 已选择音频源：{ $name }[#{ $index }]
cli-selected-audio-source = 已选择音频源：{ $name }
cli-selected-audio-source-pos = 已选择音频源：{ $name }:{ $pos }

# CLI: network / renderer discovery
cli-found-network = 找到网络：{ $ip }
cli-available-renderer = 可用渲染器 #{ $n }：{ $name } 位于 { $addr }
cli-default-renderer-ip = 默认渲染器 IP：{ $ip } => { $addr }
cli-active-renderer = 活动渲染器：{ $name } => { $addr }
cli-default-player-ip = 默认播放器 IP = { $ip }
cli-no-renderers = 未找到渲染器！！！

# CLI: Ctrl-C shutdown
cli-received-ctrlc = 收到 ^C -> 正在退出。
cli-ctrlc-stopping = ^C：正在停止向 { $name } 的流媒体传输
cli-ctrlc-no-connections = ^C：没有活动的 HTTP 流媒体连接
cli-ctrlc-timeout = ^C：等待 HTTP 流媒体关闭超时 - 正在退出。

# Streaming server messages
srv-listening = 流媒体服务器正在监听 http://{ $addr }/stream/swyh.wav
srv-default-streaming = 默认流媒体采样率：{ $rate }，每采样位数：{ $bps }，格式：{ $format }
srv-start-error = 启动服务器线程时出错：{ $error }
srv-thread-error = 服务器线程以错误 { $error } 结束
srv-streaming-request = 来自 { $addr } 的流媒体请求 { $url }
srv-feedback-error = HTTP 服务器：写入反馈通道时出错 { $error }
srv-streaming-info = 正在流式传输 { $audio }，输入采样格式 { $fmt }，声道数=2，采样率={ $rate }，位数 = { $bps }，到 { $addr }
srv-http-terminated = =>与 { $addr } 的 HTTP 连接已终止 [{ $error }]
srv-streaming-ended = 到 { $addr } 的流媒体传输已结束
srv-head-terminated = =>与 { $addr } 的 HTTP HEAD 连接已终止 [{ $error }]
srv-unsupported-method = 来自 { $addr } 的不支持的 HTTP 方法请求 { $method }
srv-bad-request = 来自 '{ $addr }' 的无法识别的请求 '{ $url }'
srv-stream-terminated = =>与 { $addr } 的 HTTP 流媒体请求已终止 [{ $error }]

srv-range-not-satisfiable = 来自 { $addr } 的范围请求无法满足，响应 416
audio-downmix = 将 { $channels } 声道输入下混为立体声进行流式传输 (ITU-R BS.775)
