import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const sidebars: SidebarsConfig = {
	docsSidebar: [
		'intro',
		'eip-8141',
		'viem-frame-tx',
		{
			type: 'category',
			label: 'Recipes',
			link: {type: 'doc', id: 'recipes/index'},
			items: ['recipes/nostr-frame-account', 'recipes/lightning-rsa'],
		},
		{
			type: 'category',
			label: 'The grimoire',
			link: {type: 'doc', id: 'grimoire/index'},
			items: [
				'grimoire/toy-curve-ecdh',
				{
					type: 'category',
					label: 'YoloRSA',
					link: {type: 'doc', id: 'grimoire/yolo-rsa'},
					items: ['grimoire/yolo-rsa-wide'],
				},
			],
		},
	],
};

export default sidebars;
