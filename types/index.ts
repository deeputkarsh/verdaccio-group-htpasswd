import { Config } from '@verdaccio/types';

export interface CustomConfig extends Config {
  foo: string;
}

export interface AuthConf {
  files: FileConf[];
  max_users: number;
}

export interface FileConf {
  isDefault: boolean;
  file: string;
  groupName: string;
  path?: string;
  lastTime?: Date;
}

export interface User {
  passwd: string;
  groups: string[];
}
