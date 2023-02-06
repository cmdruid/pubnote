import commonjs from '@rollup/plugin-commonjs'

const treeshake = {
	moduleSideEffects: false,
	propertyReadSideEffects: false,
	tryCatchDeoptimization: false
}

const nodeConfig = {
  input: './pubnote.mjs',
  output: [
    {
      file: 'build/bundle.js',
      format: 'cjs'
    },
  ],
  plugins: [ commonjs() ],
  treeshake
}

export default [ nodeConfig ]
