'use strict';
'require view';
'require form';
'require rpc';
'require poll';
'require ui';

const getStatus = rpc.declare({ object: 'luci.coredns', method: 'subscription_status', reject: true });
const update = rpc.declare({ object: 'luci.coredns', method: 'update_subscriptions', reject: true });

function statusText(result) {
	switch (result?.status) {
	case '': return _('No update recorded since boot.');
	case 'running': return _('Updating…');
	case 'success': return _('Rules updated successfully.');
	case 'no_sources': return _('Enable and apply at least one subscription entry.');
	case 'invalid_entry': return _('A subscription has an invalid filename or required field.');
	case 'duplicate_file': return _('Two enabled subscriptions in the same group use the same filename.');
	case 'geosite_failed': return _('Could not download or validate GeoSite. Check the mirror URL and the categories in /etc/coredns/local.txt and /etc/coredns/remote.txt.');
	case 'block_failed': return _('Could not download or validate the blocking rules.');
	case 'config_failed': return _('Corefile validation failed; previous rules restored.');
	case 'restart_failed': return _('CoreDNS restart failed; previous rules restored.');
	case 'rollback_failed': return _('Could not restore previous rules. Check the system log.');
	case 'interrupted': return _('Update was interrupted.');
	case 'storage': return _('Could not write rule files.');
	default: return _('Update status unavailable.');
	}
}

return view.extend({
	render() {
		const map = new form.Map('coredns-subscriptions', _('Subscriptions'),
			_('Update all enabled subscriptions together every day or every week (router local time).'));
		const section = map.section(form.NamedSection, 'main', 'schedule', _('Schedule'),
			_('The schedule and Update now apply to both routing and blocking subscriptions.'));
		const enabled = section.option(form.Flag, 'enabled', _('Enable scheduled updates'));
		enabled.rmempty = false;

		const frequency = section.option(form.ListValue, 'frequency', _('Update frequency'));
		frequency.value('daily', _('Daily'));
		frequency.value('weekly', _('Weekly'));
		frequency.default = 'weekly';
		frequency.rmempty = false;

		const weekday = section.option(form.ListValue, 'weekday', _('Day of week'));
		[ _('Sunday'), _('Monday'), _('Tuesday'), _('Wednesday'), _('Thursday'), _('Friday'), _('Saturday') ]
			.forEach((day, i) => weekday.value(String(i), day));
		weekday.default = '0';
		weekday.rmempty = false;
		weekday.retain = true;
		weekday.depends('frequency', 'weekly');

		const hour = section.option(form.ListValue, 'hour', _('Time of day'));
		for (let i = 0; i < 24; i++)
			hour.value(String(i), String(i).padStart(2, '0') + ':00');
		hour.rmempty = false;

		const status = E('strong', { 'aria-live': 'polite' }, [ _('Collecting data ...') ]);
		const refresh = async () => { status.textContent = statusText(await getStatus().catch(() => null)); };
		const updateBar = E('div', { class: 'cbi-section' }, [
			E('p', {}, [ _('Uses applied settings. CoreDNS picks up updated rules at the configured reload interval.') ]),
			E('button', {
				type: 'button',
				class: 'cbi-button cbi-button-action',
				disabled: !L.hasViewPermission() || null,
				click: ui.createHandlerFn(this, async () => {
					try {
						const reply = await update();
						if (!reply?.queued)
							throw new Error(_('Could not queue the update.'));
						await refresh();
					}
					catch (error) {
						ui.addNotification(null, E('p', {}, [ error.message ]), 'error');
					}
				})
			}, [ _('Update now') ]),
			' ', status
		]);
		map.description = E('div', {}, [ E('p', {}, [ map.description ]), updateBar ]);

		const routing = map.section(form.NamedSection, 'main', 'routing', _('Routing'));
		const routingEnabled = routing.option(form.Flag, 'routing_enabled', _('Update routing rules'));
		routingEnabled.default = '1';
		routingEnabled.rmempty = false;

		const source = routing.option(form.ListValue, 'geosite_source', _('Download source'),
			_('Choose where to download Loyalsoldier’s geosite.dat. Categories are selected in /etc/coredns/local.txt and /etc/coredns/remote.txt.'));
		source.value('disabled', _('Do not update GeoSite'));
		source.value('github', _('GitHub Releases'));
		source.value('jsdelivr', _('jsDelivr'));
		source.value('custom', _('Custom mirror (e.g. ghproxy)'));
		source.default = 'github';
		source.rmempty = false;

		const mirror = routing.option(form.Value, 'geosite_url', _('GeoSite download URL'),
			_('Enter the complete HTTPS URL for geosite.dat, including any mirror prefix.'));
		mirror.placeholder = 'https://mirror.example/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat';
		mirror.depends('geosite_source', 'custom');
		mirror.retain = true;
		mirror.rmempty = false;
		mirror.validate = (sectionId, value) => /^https:\/\/[^\s/]+[^\s]*$/.test(value) || _('Enter a valid HTTPS URL.');

		{
			const type = 'block', title = _('Blocking'), dir = '/etc/coredns/adblock/', reserved = 'allowlist.txt';
			const blocking = map.section(form.NamedSection, 'main', type, title);
			const blockingEnabled = blocking.option(form.Flag, 'blocking_enabled', _('Update blocking rules'));
			blockingEnabled.default = '1';
			blockingEnabled.rmempty = false;
			const list = map.section(form.GridSection, type, _('Blocking subscriptions'),
				_('Files are stored in %s. Reference custom filenames in the Corefile to use them. Disabling or deleting a row does not delete its file or stop CoreDNS using it.').format(dir));
			list.anonymous = true;
			list.addremove = true;

			const active = list.option(form.Flag, 'enabled', _('Enabled'));
			active.default = '1';
			active.rmempty = false;

			const alias = list.option(form.Value, 'alias', _('Alias'));
			alias.rmempty = false;

			const filename = list.option(form.Value, 'filename', _('Filename'));
			filename.rmempty = false;
			filename.placeholder = 'blocklist.txt';
			filename.validate = (sectionId, value) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,75}\.txt$/.test(value) && value !== reserved
				|| _('Enter a non-reserved .txt filename (up to 80 characters, no directories).');

			const url = list.option(form.Value, 'url', _('Subscription URL'));
			url.rmempty = false;
			url.placeholder = 'https://example.org/domains.txt';
			url.validate = (sectionId, value) => /^https:\/\/[^\s/]+[^\s]*$/.test(value) || _('Enter a valid HTTPS URL.');
		}

		return map.render().then(node => {
			poll.add(refresh, 3);
			return node;
		});
	}
});
