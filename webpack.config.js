var path = require('path');
var fs = require('fs');
var webpack = require('webpack');

var nodeModules = {};

fs.readdirSync(path.resolve(__dirname, 'node_modules')).filter(x =>
    ['.bin'].indexOf(x) === -1).forEach(mod => {
        nodeModules[mod] = `commonjs ${mod}`;
    }
);

module.exports = {
    name: 'server',
    target: 'node',
    entry: ['babel-polyfill', './lib/index.js'],
    output: {
        path: path.join(__dirname, 'dist'),
        filename: 'bundle.min.js'
    },
    module: {
        loaders: [
            {
                test: /\.js$/,
                exclude: /(node_modules|bower_components)/,
                loader: 'babel-loader',
                query: { presets: ['es2015', 'react', 'stage-2']}
            }
        ]
    },
    externals: nodeModules,
    devServer: {
        proxy: {
            '*': {
                target: 'http://localhost:3000'
            }
        }
    },
    plugins: [
        new webpack.optimize.UglifyJsPlugin({
            compress: { warnings: false }
        })
    ]
}
