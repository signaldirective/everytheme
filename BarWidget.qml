import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui

// EveryTheme bar button.
//
// Owns the bridge to the helper daemon and hosts the device menu. The daemon
// does all networking and crypto; this file just spawns it (once per machine,
// the daemon itself de-duplicates), keeps a Unix-socket connection open, and
// exposes a small JSON-RPC surface to Panel.qml through `hostWidget`.
BarWidget {
  id: root
  moduleName: "io.github.signaldirective.everytheme"

  // ---- daemon wiring --------------------------------------------------- //
  readonly property string runtimeDir: Quickshell.env("XDG_RUNTIME_DIR") || "/tmp"
  readonly property string socketPath: root.runtimeDir + "/everytheme.sock"
  readonly property string stateDir: (Quickshell.env("HOME") || "") + "/.config/omarchy/everytheme"
  readonly property string helperPath:
    Qt.resolvedUrl("helper/everytheme_helper.py").toString().replace("file://", "")

  property var snapshot: ({ identity: ({}), theme: "", peers: [], discovered: [], pairing: null })
  property bool online: false
  property int nextId: 1
  property var callbacks: ({})

  readonly property var peers: root.snapshot && root.snapshot.peers ? root.snapshot.peers : []
  readonly property int enabledPeers: {
    var n = 0
    var list = root.peers
    for (var i = 0; i < list.length; i++) if (list[i].enabled) n++
    return n
  }

  function rpc(cmd, args, callback) {
    var id = root.nextId++
    if (callback) root.callbacks[id] = callback
    sock.write(JSON.stringify({ id: id, cmd: cmd, args: args || {} }) + "\n")
    return id
  }

  function handleLine(line) {
    if (!line || line.length === 0) return
    var msg
    try { msg = JSON.parse(line) } catch (e) { return }
    if (msg.event === "state") { root.snapshot = msg.data; return }
    if (msg.id !== undefined && root.callbacks[msg.id]) {
      var cb = root.callbacks[msg.id]
      delete root.callbacks[msg.id]
      cb(msg)
    }
  }

  // ---- popup contract (open/close/opened on the bar-widget root) ------- //
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function open() { if (panelLoader.item) panelLoader.item.open() }
  function close() { if (panelLoader.item) panelLoader.item.close() }
  function togglePanel() { if (panelLoader.item) panelLoader.item.toggle() }

  function injectPanel() {
    var panel = panelLoader.item
    if (!panel) return
    if ("bar" in panel) panel.bar = root.bar
    if ("settings" in panel) panel.settings = root.settings
    if ("anchorItem" in panel) panel.anchorItem = button
    if ("hostWidget" in panel) panel.hostWidget = root
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

  Process {
    id: helper
    command: ["/usr/bin/python3", root.helperPath, "--state-dir", root.stateDir,
              "--socket", root.socketPath, "daemon"]
    running: true
    onExited: function(exitCode, exitStatus) { restartTimer.restart() }
  }

  // A second monitor's widget spawns a daemon that finds the socket already
  // live and exits immediately; we only restart if the socket is dead too.
  Timer {
    id: restartTimer
    interval: 3000
    onTriggered: if (!sock.connected) helper.running = true
  }

  Socket {
    id: sock
    path: root.socketPath
    parser: SplitParser {
      splitMarker: "\n"
      onRead: function(line) { root.handleLine(line) }
    }
    onConnectionStateChanged: root.online = sock.connected
    onError: function(error) { root.online = false }
  }

  // The Socket drops our binding on disconnect, so re-assert it rather than
  // relying on the `connected` property to stay bound.
  Timer {
    interval: 1500
    running: true
    repeat: true
    onTriggered: if (!sock.connected) sock.connected = true
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰏘"
    tooltipText: root.peers.length > 0
      ? ("EveryTheme · " + root.enabledPeers + " of " + root.peers.length + " synced")
      : "EveryTheme"
    active: root.enabledPeers > 0
    useActiveColor: root.enabledPeers > 0
    onPressed: root.togglePanel()
  }
}
