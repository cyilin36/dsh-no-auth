window.__ModuleLoader__.load({
  id: 'dsh-no-auth',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const NS = 'dshNoAuth'
    const zh = {
      section: '免 Token 直连',
      title: '免 Token 直连 / 局域网白名单',
      description:
        'dsh-no-auth 已关闭 Web 的启动 token 校验，并可用插件自带的局域网入口让其他设备访问。下面的白名单决定谁可以进入；留空表示不做 IP 限制。',
      status: '当前状态',
      loading: '加载中…',
      reload: '刷新',
      version: '插件版本',
      dshMode: 'dsh 监听模式',
      ranges: '白名单条目',
      lanEntry: '局域网入口',
      lanDisabled: '未启用',
      notListening: '未监听',
      whitelistLabel: '允许的客户端（IP / 网段）',
      whitelistHint:
        '每行一条：单个 IP（如 192.168.1.42）或 CIDR 网段（如 192.168.1.0/24、fd00::/8）。留空 = 0.0.0.0/0（任何可达客户端都可进入）。填写后白名单就是唯一入口，名单外即使有有效 token 也会被拒绝。',
      emptyOpen: '当前白名单为空：等价于 0.0.0.0/0，任何能连到该端口的客户端都会以 owner 身份进入。',
      lanEnable: '启用插件自带局域网入口',
      lanHost: '监听地址',
      lanPort: '监听端口',
      lanHint:
        '监听地址必须是本机一个具体接口地址（不能是 0.0.0.0）。端口被占用时（例如已有反向代理占用该端口）监听会失败，可换端口或先停掉占用进程。',
      save: '保存并应用',
      saving: '保存中…',
      saved: '已保存并即时生效',
      saveFailed: '保存失败',
      loadFailed: '读取设置失败',
      yes: '是',
      no: '否',
    }
    const en = {
      section: 'No-Auth Direct Access',
      title: 'No-Auth Direct Access / LAN whitelist',
      description:
        'dsh-no-auth disables the Web launch token and can expose the GUI to the LAN through its own listener. The whitelist below decides who gets in; an empty list means no IP restriction.',
      status: 'Status',
      loading: 'Loading…',
      reload: 'Reload',
      version: 'Plugin version',
      dshMode: 'dsh listener mode',
      ranges: 'Whitelist entries',
      lanEntry: 'LAN listener',
      lanDisabled: 'Disabled',
      notListening: 'Not listening',
      whitelistLabel: 'Allowed clients (IP / CIDR)',
      whitelistHint:
        'One per line: a single IP (e.g. 192.168.1.42) or a CIDR range (e.g. 192.168.1.0/24, fd00::/8). Empty = 0.0.0.0/0 (any reachable client is admitted). A non-empty list is the only entry: clients outside it are refused even with a valid token.',
      emptyOpen:
        'The whitelist is empty: equivalent to 0.0.0.0/0, so any client that can reach the port enters as the owner.',
      lanEnable: 'Enable the plugin LAN listener',
      lanHost: 'Listen address',
      lanPort: 'Listen port',
      lanHint:
        'The address must be one concrete local interface address (never 0.0.0.0). If the port is taken (for example another process already owns that port) the listener fails; pick another port or stop the owner first.',
      save: 'Save and apply',
      saving: 'Saving…',
      saved: 'Saved and applied',
      saveFailed: 'Save failed',
      loadFailed: 'Could not load settings',
      yes: 'Yes',
      no: 'No',
    }

    const styles = {
      box: { display: 'flex', flexDirection: 'column', gap: '16px', maxWidth: '760px', padding: '4px 0 24px' },
      heading: { margin: 0, fontSize: '18px', fontWeight: 600 },
      hint: { margin: 0, fontSize: '12px', lineHeight: 1.7, opacity: 0.72 },
      card: {
        padding: '10px 12px',
        border: '1px solid rgba(127,127,127,.28)',
        borderRadius: '10px',
        fontSize: '12px',
        lineHeight: 1.8,
      },
      label: { display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px', fontWeight: 500 },
      textarea: {
        width: '100%',
        minHeight: '120px',
        resize: 'vertical',
        padding: '8px 10px',
        borderRadius: '8px',
        border: '1px solid rgba(127,127,127,.35)',
        background: 'transparent',
        color: 'inherit',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: '13px',
        lineHeight: 1.6,
        boxSizing: 'border-box',
      },
      input: {
        padding: '7px 10px',
        borderRadius: '8px',
        border: '1px solid rgba(127,127,127,.35)',
        background: 'transparent',
        color: 'inherit',
        fontSize: '13px',
        boxSizing: 'border-box',
      },
      inlineLabel: { display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px', fontWeight: 500 },
      checkboxRow: { display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', fontWeight: 500 },
      row: { display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' },
      primary: {
        alignSelf: 'flex-start',
        padding: '7px 18px',
        borderRadius: '8px',
        border: 'none',
        background: 'var(--dsw-alias-button-primary-bg, #1f6feb)',
        color: '#fff',
        cursor: 'pointer',
        fontSize: '13px',
      },
      secondary: {
        alignSelf: 'flex-start',
        padding: '7px 14px',
        borderRadius: '8px',
        border: '1px solid rgba(127,127,127,.35)',
        background: 'transparent',
        color: 'inherit',
        cursor: 'pointer',
        fontSize: '13px',
      },
      ok: { margin: 0, fontSize: '12px', color: '#2e8b57' },
      error: { margin: 0, fontSize: '12px', color: '#d9534f', whiteSpace: 'pre-wrap' },
    }

    /**
     * Call the Host settings endpoint relative to the page base.
     * @param method - HTTP method.
     * @param body - optional JSON payload.
     * @returns parsed JSON payload.
     */
    async function callSettings(method, body) {
      const response = await fetch('api/dsh-no-auth/settings', {
        method,
        cache: 'no-store',
        headers: body === undefined ? undefined : { 'content-type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await response.text()
      let data
      try {
        data = JSON.parse(text)
      } catch {
        throw new Error(text || `HTTP ${response.status}`)
      }
      if (response.ok !== true || data.ok !== true) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data
    }

    /**
     * Render one status line.
     * @param label - translated label.
     * @param value - rendered value.
     */
    function statusRow(label, value) {
      return h(
        'div',
        { style: { display: 'flex', gap: '10px' } },
        h('span', { style: { opacity: 0.7, minWidth: '120px' } }, label),
        h('span', null, value),
      )
    }

    /**
     * The settings section contributed to the DSH Settings shell.
     * @param props - slot props carrying the bound translator.
     */
    function SettingsSection(props) {
      const t = props.t
      const [phase, setPhase] = React.useState('loading')
      const [error, setError] = React.useState(null)
      const [data, setData] = React.useState(null)
      const [entriesText, setEntriesText] = React.useState('')
      const [lanEnabled, setLanEnabled] = React.useState(false)
      const [lanHost, setLanHost] = React.useState('')
      const [lanPort, setLanPort] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [message, setMessage] = React.useState(null)

      const load = React.useCallback(async () => {
        setPhase('loading')
        setError(null)
        try {
          const next = await callSettings('GET')
          setData(next)
          setEntriesText(next.settings.allowedClients.join('\n'))
          setLanEnabled(next.settings.lanProxy.enabled)
          setLanHost(next.settings.lanProxy.host)
          setLanPort(String(next.settings.lanProxy.port))
          setPhase('ready')
        } catch (reason) {
          setError(String((reason && reason.message) || reason))
          setPhase('error')
        }
      }, [])

      React.useEffect(() => {
        void load()
      }, [load])

      const save = React.useCallback(async () => {
        setBusy(true)
        setMessage(null)
        try {
          const allowedClients = entriesText
            .split(/[\s,，;；]+/u)
            .map((entry) => entry.trim())
            .filter((entry) => entry !== '')
          const next = await callSettings('POST', {
            allowedClients,
            lanProxy: {
              enabled: lanEnabled,
              host: lanHost.trim(),
              port: Number(lanPort),
            },
          })
          setData(next)
          setEntriesText(next.settings.allowedClients.join('\n'))
          setLanEnabled(next.settings.lanProxy.enabled)
          setLanHost(next.settings.lanProxy.host)
          setLanPort(String(next.settings.lanProxy.port))
          setMessage({ kind: 'ok', text: t('saved') })
        } catch (reason) {
          setMessage({ kind: 'error', text: `${t('saveFailed')}: ${String((reason && reason.message) || reason)}` })
        } finally {
          setBusy(false)
        }
      }, [entriesText, lanEnabled, lanHost, lanPort, t])

      const status = data === null ? null : data.status
      const lanStatus =
        status === null
          ? ''
          : status.lan.listening === true
            ? `${t('yes')} — ${status.lan.url}`
            : status.lan.error !== null && status.lan.error !== undefined
              ? `${t('no')} — ${status.lan.error}`
              : t('notListening')

      return h(
        'div',
        { style: styles.box },
        h('h2', { style: styles.heading }, t('title')),
        h('p', { style: styles.hint }, t('description')),

        h(
          'div',
          { style: styles.card },
          h('div', { style: { fontWeight: 600, marginBottom: '4px' } }, t('status')),
          phase === 'loading' ? h('div', null, t('loading')) : null,
          phase === 'error'
            ? h('div', { style: styles.error }, `${t('loadFailed')}: ${error}`)
            : null,
          status === null
            ? null
            : h(
                'div',
                { style: { display: 'flex', flexDirection: 'column', gap: '2px' } },
                statusRow(t('version'), data.version),
                statusRow(t('dshMode'), status.mode),
                statusRow(t('ranges'), String(status.ranges)),
                statusRow(t('lanEntry'), lanStatus),
              ),
        ),

        h(
          'label',
          { style: styles.label },
          t('whitelistLabel'),
          h('textarea', {
            style: styles.textarea,
            value: entriesText,
            spellCheck: false,
            placeholder: '192.168.1.42\n192.168.1.0/24\nfd00::/8',
            onChange: (event) => setEntriesText(event.target.value),
          }),
        ),
        h('p', { style: styles.hint }, t('whitelistHint')),
        status !== null && status.ranges === 0
          ? h('p', { style: styles.hint }, t('emptyOpen'))
          : null,

        h(
          'label',
          { style: styles.checkboxRow },
          h('input', {
            type: 'checkbox',
            checked: lanEnabled,
            onChange: (event) => setLanEnabled(event.target.checked),
          }),
          t('lanEnable'),
        ),
        h(
          'div',
          { style: styles.row },
          h(
            'label',
            { style: styles.inlineLabel },
            t('lanHost'),
            h('input', {
              style: { ...styles.input, width: '200px' },
              value: lanHost,
              spellCheck: false,
              onChange: (event) => setLanHost(event.target.value),
            }),
          ),
          h(
            'label',
            { style: styles.inlineLabel },
            t('lanPort'),
            h('input', {
              style: { ...styles.input, width: '110px' },
              type: 'number',
              min: 1,
              max: 65535,
              value: lanPort,
              onChange: (event) => setLanPort(event.target.value),
            }),
          ),
        ),
        h('p', { style: styles.hint }, t('lanHint')),

        message === null
          ? null
          : h('p', { style: message.kind === 'ok' ? styles.ok : styles.error }, message.text),

        h(
          'div',
          { style: styles.row },
          h(
            'button',
            { type: 'button', style: styles.primary, disabled: busy, onClick: save },
            busy ? t('saving') : t('save'),
          ),
          h(
            'button',
            { type: 'button', style: styles.secondary, disabled: busy, onClick: load },
            t('reload'),
          ),
        ),
      )
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-no-auth: dictionaries')
        const t = ctx.locale.bind(NS)
        ctx.slots.inject('settings.section', () =>
          ctx.slots.register(
            {
              name: 'settings.section',
              id: 'dsh-no-auth',
              order: 90,
              label: () => t('section'),
              inject: () => ({ t }),
            },
            SettingsSection,
          ),
        )
      },
    }
  },
})
