'use strict';
'require view';
'require rpc';
'require ui';

const getCorefile = rpc.declare({
	object: 'luci.coredns',
	method: 'get_corefile',
	reject: true
});

const saveCorefile = rpc.declare({
	object: 'luci.coredns',
	method: 'save_corefile',
	params: [ 'content' ],
	reject: true
});

function errorMessage(result) {
	switch (result?.error) {
	case 'empty': return _('Enter a non-empty Corefile without NUL characters.');
	case 'size': return _('The Corefile editor supports files up to 32 KiB.');
	case 'read': return _('Could not read /etc/coredns/Corefile.');
	case 'invalid':
		return result.details ? _('Corefile validation failed: %s').format(result.details) : _('Corefile validation failed.');
	default: return _('Could not save /etc/coredns/Corefile.');
	}
}

return view.extend({
	load() {
		return getCorefile();
	},

	render(result) {
		const heading = E('h2', {}, [ _('Corefile') ]);
		if (typeof result?.content !== 'string')
			return E('div', {}, [ heading, E('p', {}, [ errorMessage(result) ]) ]);

		const readonly = !L.hasViewPermission();
		const editor = E('textarea', {
			id: 'coredns-corefile',
			class: 'cbi-input-textarea',
			rows: 24,
			style: 'width: 100%; font-family: monospace;',
			wrap: 'off',
			spellcheck: 'false',
			readonly: readonly || null,
			'aria-label': _('Corefile')
		});
		editor.value = result.content;

		const save = E('button', {
			type: 'button',
			class: 'cbi-button cbi-button-save',
			click: ui.createHandlerFn(this, async () => {
				let content = editor.value.replace(/\r\n?/g, '\n');
				if (!content.endsWith('\n'))
					content += '\n';
				editor.readOnly = true;
				try {
					const response = await saveCorefile(content);
					if (!response?.saved)
						throw new Error(errorMessage(response));
					editor.value = content;
					ui.addNotification(null, E('p', {}, [ _('Corefile saved. Use Restart on the Settings page to load it.') ]), 'info');
				}
				catch (error) {
					ui.addNotification(null, E('p', {}, [ error.message ]), 'error');
				}
				finally {
					editor.readOnly = false;
				}
			})
		}, [ _('Validate and save') ]);

		return E('div', {}, [
			heading,
			E('p', {}, [ _('Edit /etc/coredns/Corefile directly to change listeners, upstreams or plugin settings. The file is checked before it replaces the current one. Saving does not restart CoreDNS.') ]),
			editor,
			readonly ? '' : E('p', {}, [ save ])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
