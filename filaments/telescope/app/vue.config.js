module.exports = {
  pluginOptions: {
    webpack: {
      dir: [
        '../../dist'
      ],
      name: "telescope"
    }
  },
  chainWebpack: config => {
    config.module
      .rule('vue')
      .use('vue-loader')
      .tap(options => {
        options.compilerOptions = {
          ...options.compilerOptions,
          isCustomElement: tag => tag.startsWith('ion-')
        }
        return options
      })
  }
}
