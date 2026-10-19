// Layer rules (design §2): core ← transport ← client ← wallet ← adapters.
const layers = ['core', 'transport', 'client', 'wallet', 'adapters']

const upward = layers.slice(0, -1).map((layer, i) => ({
  name: `${layer}-imports-upward`,
  comment: `${layer} may only import from ${layers.slice(0, i).join(', ') || 'itself'}`,
  severity: 'error',
  from: { path: `^src/${layer}/` },
  to: { path: `^src/(${layers.slice(i + 1).join('|')})/` },
}))

module.exports = {
  forbidden: [
    ...upward,
    {
      name: 'nothing-imports-react-bindings',
      comment: 'react sits on top: the SDK below never depends on it',
      severity: 'error',
      from: { path: '^src/(core|transport|client|wallet|adapters)/' },
      to: { path: '^src/react/' },
    },
    {
      name: 'react-bindings-stay-adapter-free',
      comment: 'the bindings take a wallet; which storage, vault or relays it uses is the app\'s choice',
      severity: 'error',
      from: { path: '^src/react/' },
      to: { path: '^src/(adapters|transport|client)/' },
    },
    {
      name: 'react-only-in-bindings',
      comment: 'React is an optional peer, imported by src/react alone',
      severity: 'error',
      from: { pathNot: '^src/react/' },
      to: { path: 'node_modules/(react|react-dom)/' },
    },
    {
      name: 'no-platform-in-sdk',
      comment: 'core, transport, client and wallet reach the platform only through ports (§3)',
      severity: 'error',
      from: { path: '^src/(core|transport|client|wallet)/' },
      to: { dependencyTypes: ['core'] },
    },
    {
      name: 'only-approved-packages-in-sdk',
      comment: 'no concrete relay or storage library below adapters (§2); runtime deps are noble and scure only (§12)',
      severity: 'error',
      from: { path: '^src/(core|transport|client|wallet)/' },
      to: {
        dependencyTypes: ['npm', 'npm-dev', 'npm-optional', 'npm-peer', 'npm-no-pkg', 'npm-unknown'],
        pathNot: 'node_modules/@(noble/(curves|hashes|ciphers)|scure/base)/',
      },
    },
    {
      name: 'no-circular',
      severity: 'error',
      from: {},
      to: { circular: true },
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsConfig: { fileName: 'tsconfig.json' },
    enhancedResolveOptions: { exportsFields: ['exports'], conditionNames: ['import', 'types'] },
  },
}
