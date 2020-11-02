const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const webpack = require('webpack');
const config = {
    entry: "./scripts/index.js",
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'bundle.js',
        publicPath: '/public/'
    },
    resolve: {
        extensions: ['.js', '.jsx', '.css', '.ts']
    },
  
    module: {
        rules: [
            {
            test: /\.(js|jsx)?/,
                exclude: /node_modules/,
                use: {
                    loader : 'babel-loader' 
                }
            }        
        ]
    }
};
module.exports = config;