import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui

// The EveryTheme device menu.
//
// Read-only view over `hostWidget.state` (pushed by the helper daemon) plus a
// few commands sent back over the same Unix socket. All trust decisions live
// in the daemon; this file only presents them.
Panel {
  id: root
  moduleName: "io.github.signaldirective.everytheme"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null

  readonly property var snapshot: hostWidget ? hostWidget.snapshot : ({})
  readonly property var identity: snapshot && snapshot.identity ? snapshot.identity : ({})
  readonly property var peers: snapshot && snapshot.peers ? snapshot.peers : []
  readonly property var discovered: snapshot && snapshot.discovered ? snapshot.discovered : []
  readonly property var pairing: snapshot && snapshot.pairing ? snapshot.pairing : null
  readonly property string currentTheme: snapshot && snapshot.theme ? snapshot.theme : ""

  readonly property color fg: bar ? bar.foreground : Color.foreground
  readonly property color dim: Qt.darker(fg, 1.6)
  readonly property color accent: Color.accent
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // UI-local state for the "enter a code" step.
  property var pairingTarget: null
  property string codeInput: ""
  property string statusText: ""

  function open() { root.controller.show() }
  function close() { root.controller.hide() }
  function toggle() { if (root.opened) root.close(); else root.open() }

  function startPairing() {
    root.statusText = ""
    if (hostWidget) hostWidget.rpc("pair.start")
  }
  function cancelPairing() {
    root.statusText = ""
    if (hostWidget) hostWidget.rpc("pair.cancel")
  }
  function beginAccept(device) {
    root.pairingTarget = device
    root.codeInput = ""
    root.statusText = ""
    Qt.callLater(function() { codeField.forceActiveFocus() })
  }
  function cancelAccept() {
    root.pairingTarget = null
    root.codeInput = ""
    root.statusText = ""
  }
  function doAccept() {
    if (!root.pairingTarget || !hostWidget) return
    var device = root.pairingTarget
    hostWidget.rpc("pair.accept",
      { host: device.address, port: device.pair_port, code: root.codeInput },
      function(res) {
        if (res && res.ok) {
          root.pairingTarget = null
          root.statusText = "Paired with " + (res.data && res.data.peer ? res.data.peer.name : "device")
        } else {
          root.statusText = "Pairing failed: " + (res && res.error ? res.error : "unknown error")
        }
      })
  }
  function removePeer(id) { if (hostWidget) hostWidget.rpc("peer.remove", { id: id }) }
  function setEnabled(id, value) { if (hostWidget) hostWidget.rpc("peer.enabled", { id: id, enabled: value }) }
  function shortId(peer) {
    if (peer.fingerprint) return peer.fingerprint.slice(0, 12)
    if (peer.addresses && peer.addresses.length) return peer.addresses[0]
    return ""
  }

  KeyboardPanel {
    id: kpanel
    anchorItem: root.anchorItem
    owner: root.hostWidget || root
    bar: root.bar
    open: root.opened
    centerOnBar: true
    contentWidth: kpanel.fittedContentWidth(Style.space(430))
    contentHeight: kpanel.fittedContentHeight(body.implicitHeight)
    focusTarget: keys

    PanelKeyCatcher {
      id: keys
      anchors.fill: parent
      blocked: codeField.activeFocus

      Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: body.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        Column {
          id: body
          width: scroll.width
          spacing: Style.spacing.rowGap

          // ---- header -------------------------------------------------- //
          Row {
            width: body.width
            spacing: Style.space(10)

            Text {
              text: "󰏘"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.iconLarge
              anchors.verticalCenter: parent.verticalCenter
            }
            Column {
              spacing: 0
              anchors.verticalCenter: parent.verticalCenter
              Text {
                text: "EveryTheme"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
              }
              Text {
                text: root.identity.name
                  ? (root.identity.name + " · " + String(root.identity.id).slice(0, 8))
                  : "starting…"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }

          // ---- pairing: this device shows the code --------------------- //
          BorderSurface {
            visible: root.pairing !== null
            width: body.width
            implicitHeight: codeCol.implicitHeight + Style.spacing.popupPadding * 2
            color: Style.normalFillFor(root.fg, root.accent)
            radius: Style.cornerRadius
            borderSpec: Border.controlSpec("normal", root.fg, root.accent)

            Column {
              id: codeCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.spacing.popupPadding
              anchors.rightMargin: Style.spacing.popupPadding
              spacing: Style.spacing.sm

              Text {
                text: "On the other device, open EveryTheme and enter this code:"
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
                width: parent.width
              }
              Text {
                text: root.pairing ? root.pairing.code : ""
                color: root.accent
                font.family: root.fontFamily
                font.pixelSize: 28
                font.bold: true
                font.letterSpacing: 4
              }
              Text {
                visible: root.pairing && root.pairing.qr
                text: root.pairing ? "or scan: " + root.pairing.qr : ""
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                elide: Text.ElideMiddle
                width: parent.width
              }
              Button {
                text: "Cancel"
                bordered: true
                foreground: root.fg
                accent: root.accent
                fontFamily: root.fontFamily
                onClicked: root.cancelPairing()
              }
            }
          }

          // ---- pairing: entering the other device's code --------------- //
          BorderSurface {
            visible: root.pairingTarget !== null
            width: body.width
            implicitHeight: acceptCol.implicitHeight + Style.spacing.popupPadding * 2
            color: Style.normalFillFor(root.fg, root.accent)
            radius: Style.cornerRadius
            borderSpec: Border.controlSpec("focus", root.fg, root.accent)

            Column {
              id: acceptCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.spacing.popupPadding
              anchors.rightMargin: Style.spacing.popupPadding
              spacing: Style.spacing.sm

              Text {
                text: "Pairing with " + (root.pairingTarget ? root.pairingTarget.name : "")
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
              }
              TextField {
                id: codeField
                width: parent.width
                placeholderText: "6-digit code"
                foreground: root.fg
                accent: root.accent
                font.family: root.fontFamily
                inputMethodHints: Qt.ImhDigitsOnly
                onTextChanged: root.codeInput = text
                onAccepted: root.doAccept()
              }
              Row {
                spacing: Style.spacing.lg
                Button {
                  text: "Pair"
                  bordered: true
                  selected: true
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  onClicked: root.doAccept()
                }
                Button {
                  text: "Cancel"
                  bordered: true
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  onClicked: root.cancelAccept()
                }
              }
            }
          }

          // ---- paired devices ------------------------------------------ //
          PanelSectionHeader {
            visible: root.pairing === null && root.pairingTarget === null
            width: body.width
            text: "SYNCED DEVICES"
            foreground: root.fg
            fontFamily: root.fontFamily
          }

          Repeater {
            model: (root.pairing === null && root.pairingTarget === null) ? root.peers : []
            delegate: RowLayout {
              required property var modelData
              width: body.width
              spacing: Style.spacing.lg

              Column {
                Layout.fillWidth: true
                spacing: 0
                Text {
                  width: parent.width
                  text: modelData.name
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  elide: Text.ElideRight
                }
                Text {
                  width: parent.width
                  text: root.shortId(modelData)
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }
              ToggleSwitch {
                Layout.alignment: Qt.AlignVCenter
                checked: modelData.enabled
                foreground: root.fg
                accent: root.accent
                onToggled: root.setEnabled(modelData.id, !modelData.enabled)
              }
              PanelActionButton {
                Layout.alignment: Qt.AlignVCenter
                iconText: "󰅖"
                tooltipText: "Remove device"
                foreground: root.fg
                hoverColor: root.fg
                fontFamily: root.fontFamily
                onClicked: root.removePeer(modelData.id)
              }
            }
          }

          Text {
            visible: root.pairing === null && root.pairingTarget === null && root.peers.length === 0
            width: body.width
            text: "No devices yet. Pair one below to sync themes across your machines."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // ---- discovered (untrusted) devices -------------------------- //
          PanelSectionHeader {
            visible: root.pairing === null && root.pairingTarget === null
            width: body.width
            text: "ON YOUR NETWORK"
            foreground: root.fg
            fontFamily: root.fontFamily
          }

          Repeater {
            model: (root.pairing === null && root.pairingTarget === null) ? root.discovered : []
            delegate: RowLayout {
              required property var modelData
              width: body.width
              spacing: Style.spacing.lg

              Column {
                Layout.fillWidth: true
                spacing: 0
                Text {
                  width: parent.width
                  text: modelData.name
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                  elide: Text.ElideRight
                }
                Text {
                  width: parent.width
                  text: modelData.address + (modelData.pair_port ? (":" + modelData.pair_port) : "")
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  elide: Text.ElideRight
                }
              }
              Button {
                Layout.alignment: Qt.AlignVCenter
                text: "Pair"
                bordered: true
                foreground: root.fg
                accent: root.accent
                fontFamily: root.fontFamily
                onClicked: root.beginAccept(modelData)
              }
            }
          }

          Text {
            visible: root.pairing === null && root.pairingTarget === null && root.discovered.length === 0
            width: body.width
            text: "Searching your network… open EveryTheme on another machine to start pairing."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // ---- actions + status ---------------------------------------- //
          Row {
            visible: root.pairing === null && root.pairingTarget === null
            width: body.width
            spacing: Style.spacing.lg

            Button {
              text: "Pair a new device"
              iconText: "󰐕"
              bordered: true
              foreground: root.fg
              accent: root.accent
              fontFamily: root.fontFamily
              onClicked: root.startPairing()
            }
          }

          Text {
            visible: root.statusText !== ""
            width: body.width
            text: root.statusText
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Rectangle {
            width: body.width
            height: 1
            color: Qt.darker(root.fg, 2.4)
          }

          Text {
            width: body.width
            text: root.currentTheme !== ""
              ? ("Current theme: " + root.currentTheme + " — change it anywhere and EveryTheme mirrors it.")
              : "EveryTheme mirrors your theme changes to synced devices."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
        }
      }
    }
  }
}
