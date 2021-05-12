/*
 * Copyright (C) 2015-2016 Julien Chavanton
 *
 * This file is part of Disruptor, a network impairment server.
 *
 * Disruptor is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Disruptor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef DISRUPTOR_FILE_H
#define DISRUPTOR_FILE_H
#include <sys/types.h>
#include <sys/stat.h>
void log_error( const char* format, ... );
void log_debug( const char* format, ... );
void log_notice( const char* format, ... );
void log_info( const char* format, ... );

#endif
