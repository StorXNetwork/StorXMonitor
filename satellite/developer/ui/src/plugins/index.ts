import type { App } from 'vue';
import vuetify from './vuetify';
import webfontloader from './webfontloader';

export function registerPlugins(app: App) {
    app.use(vuetify);
    webfontloader();
}

