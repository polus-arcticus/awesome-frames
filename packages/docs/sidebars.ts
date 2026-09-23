import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const sidebars: SidebarsConfig = {
	docsSidebar: [
		'intro',
		'eip-8141',
		'viem-frame-tx',
		{
			type: 'category',
			label: 'Tools',
			link: {type: 'doc', id: 'tools/index'},
			items: ['tools/nostr-frame-account', 'tools/lightning-rsa', 'tools/ntrusign'],
		},
		{
			type: 'category',
			label: 'Toys',
			link: {type: 'doc', id: 'toys/index'},
			items: [
				'toys/toy-curve-ecdh',
				'toys/stark-pedersen',
				{
					type: 'category',
					label: 'YoloRSA',
					link: {type: 'doc', id: 'toys/yolo-rsa'},
					items: ['toys/yolo-rsa-wide'],
				},
				{
					type: 'category',
					label: 'Post-quantum survey',
					link: {type: 'doc', id: 'toys/post-quantum/index'},
					items: [
						'toys/post-quantum/ml-kem',
						'toys/post-quantum/lamport',
						'toys/post-quantum/falcon',
						'toys/post-quantum/ml-dsa',
						'toys/post-quantum/mceliece',
						'toys/post-quantum/isogeny',
					],
				},
			],
		},
	],
};

export default sidebars;
