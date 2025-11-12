import { createApp } from 'vue';
import App from './App.vue';
import { registerPlugins } from '@/plugins';
import router from '@/router';
import { createPinia } from 'pinia';

const app = createApp(App);
const pinia = createPinia();

registerPlugins(app);

app.use(pinia);
app.use(router);

app.mount('#app');

