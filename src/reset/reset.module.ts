import { Module } from '@nestjs/common';
import { ResetService } from './reset.service';
import { ResetController } from './reset.controller';
import {TypeOrmModule} from '@nestjs/typeorm'
import {ResetEntity} from './reset.entity'

@Module({
  imports:[TypeOrmModule.forFeature([ResetEntity]),],
  providers: [ResetService],
  controllers: [ResetController]
})
export class ResetModule {}
