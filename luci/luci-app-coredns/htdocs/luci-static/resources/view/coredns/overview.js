'use strict';
'require view';
'require form';
'require fs';
'require poll';
'require rpc';
'require ui';

const listService = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} },
	reject: true
});

function refreshStatus(status) {
	return listService('coredns').then(services => {
		const instances = services.coredns?.instances ?? {};
		const running = Object.values(instances).some(instance => instance.running === true);
		status.textContent = running ? _('Running') : _('Not running');
	}, () => {
		status.textContent = _('Status unavailable');
	});
}

async function runCommand(path, args) {
	const result = await fs.exec(path, args);
	if (result.code !== 0)
		throw new Error((result.stderr || result.stdout || '').trim() || _('Command failed'));
}

return view.extend({
	render() {
		const map = new form.Map('coredns', _('CoreDNS'),
			_('By default, CoreDNS listens on [::]:53 and does not change dnsmasq settings. Restrict DNS access to trusted networks with the firewall.'));
		const section = map.section(form.NamedSection, 'main', 'coredns', _('Settings'));
		const status = E('strong', { 'aria-live': 'polite' }, [ _('Collecting data ...') ]);
		const statusOption = section.option(form.DummyValue, '_status', _('Service status'));
		statusOption.renderWidget = () => status;

		const enabled = section.option(form.Flag, 'enabled', _('Enable CoreDNS'),
			_('Use Save & Apply to start or stop the service and change whether it runs at boot.'));
		enabled.default = '0';
		enabled.rmempty = false;

		const restart = section.option(form.Button, '_restart', _('Restart'),
			_('Checks the Corefile before restarting. Uses the saved configuration and only starts CoreDNS if enabled.'));
		restart.inputstyle = 'action';
		restart.onclick = async () => {
			try {
				await runCommand('/usr/bin/coredns', [ '-check-config', '/etc/coredns/Corefile' ]);
				await runCommand('/etc/init.d/coredns', [ 'restart' ]);
			}
			catch (error) {
				ui.addNotification(null, E('p', {}, [ _('Could not restart CoreDNS: %s').format(error.message) ]), 'error');
			}
			await refreshStatus(status);
		};

		return map.render().then(node => {
			poll.add(() => refreshStatus(status));
			return node;
		});
	}
});
